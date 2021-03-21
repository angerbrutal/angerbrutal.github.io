---
title: "1. HackTheBox DIY with Rust: Delivery"
date: 2021-03-17T20:55:36+01:00
author: angerbrutal
draft: false
---

## Introduction

This will be a series of HTB writeups, but instead of using the same boring tools as always, I will try to create my own toolset using Rust. The goal is to have fun hacking boxes and at the same time **learn** a new language.

Some things to keep in mind:
1. I suck at pentesting.<br />
2. I suck even more at Rust programming.

Let's go.
## Setup

### Hacker name

The first thing we need is a hacker name. For this purpose I highly recommend this site: https://thestoryshack.com/tools/hacker-name-generator/.

The first name that popped up was _angerbrutal_, nice.

### Attack box

I really don't like messing with VirtualBox and I despise a bloated parrotkalilinux. Therefore I decided to go for a $5/m DigitalOcean VPS running Ubuntu. 

## First box - Delivery

To minimize the chance I'll get stuck on the first box and give up on this whole thing, I'll choose the easiest box available: Delivery.

![](/1/delivery.png)

Nice. We got an attack box and our first target. Now, we need to connect to the HTB lab's VPN. So do we pull up Rust and spend a few months coding a VPN client? No, we don't.

Let's set some constraints. My plan here is not to create everything from scratch. What I choose to create from scratch will be based on these factors:

1. Time (i.e. I won't spend [1+ year creating my own ELF-loader](https://fasterthanli.me/series/making-our-own-executable-packer/part-1) (respekk))
2. Amount of fun I think I will have doing it
3. The points above are lies and the only constraints are my own skill level

## Tool 1: Portscanner

Let's start simple and create a portscanner using a basic TCP connect `(SYN/SYN-ACK/ACK)` as its scan method.
I'm assuming an our first box is not deploying any advanced firewall techniques.

Scanning through the Rust docs tells us the networking stuff lives in `std::net`, and our first take looks like this:
```rust
use std::{net::{SocketAddr, IpAddr, TcpStream, Shutdown}, time::Duration};

fn main() -> anyhow::Result<()> {
    let ports = 1..100u16;
    let timeout = Duration::from_secs(1);
    let target = "192.168.50.1";

    let ipaddr = IpAddr::V4(target.parse()?);
    for port in ports {
        let saddr = SocketAddr::new(ipaddr, port);
        let res = TcpStream::connect_timeout(&saddr, timeout);
        if let Ok(stream) = res {
            println!("OPEN {}", port);
            stream.shutdown(Shutdown::Both)?
        }
    };

    Ok(())
}
```
<br />
Breakdown:
- As a first attempt, this will scan ports 1-100 on my router, `192.168.50.1` (please don't hack), with a timeout of 1 second.
- While learning Rust I've spent 90% if the time casting, boxing, juggling error types. So instead of taking 10 minutes to read the docs and actually learn how they work, I'm using this excellent crate called [Anyhow](https://docs.rs/anyhow/1.0.39/anyhow/).

Does it work?
```shell
$ cargo run
   Compiling portscan v0.1.0 (/home/angerbrutal/portscan)
    Finished dev [unoptimized + debuginfo] target(s) in 1.95s
     Running `target/debug/portscan`
OPEN 53
OPEN 80
```
<br />
Looks promising! To be able to reuse this scanner for other boxes it would be nice to make it configurable. For this we will use the [Clap crate](https://crates.io/crates/clap).

I would like the usage to look something like:
`portscanner -t 1000 -p 1-100 192.168.50.1`

To do this, first of all we need something to represent our port range:
```rust
struct PortRange(u16, u16);

impl PortRange {
    fn default() -> PortRange {
        PortRange(1, u16::MAX)
    }
}
```
<br />
Here we have a newtype representing the start and end port, with a default constructor of `1-65535`.

We also need to be able to create a `PortRange` from our string input:
```rust
impl FromStr for PortRange {
    type Err = Box<dyn std::error::Error>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.contains('-') {
            let parts: Vec<&str> = s.split('-').collect();
            if let [start, end] = &parts[..] {
                Ok(PortRange(start.parse::<u16>()?, end.parse::<u16>()?))
            } else {
                Err(anyhow::anyhow!("invalid port range").into())
            }
        } else {
            let port = s.parse::<u16>()?;
            Ok(PortRange(port, port))
        }
    }
}
```
<br />
Now we are ready to model our arguments in Clap-lang and parse it:
```rust
#[derive(Clap, Debug)]
struct Opts {
    target: String,
    #[clap(short)]
    ports: Option<PortRange>,
    #[clap(short)]
    timeout: Option<u64>,
}

fn main() -> anyhow::Result<()> {
    let opts: Opts = Opts::parse();

    let target = opts.target;
    let ports = opts.ports.unwrap_or_else(PortRange::default);
    let timeout = Duration::from_millis(opts.timeout.unwrap_or(500));

    println!("Scanning {} - {:?} - {}ms timeout..", target, ports, timeout.as_millis());

    let ipaddr = IpAddr::V4(target.parse()?);
    for port in ports.0..ports.1 {
        if knock(&ipaddr, port, timeout).is_ok() {
            println!("OPEN {}", port);
        }
    };

    Ok(())
}
```
<br />
Let's try it out with the default arguments!

```shell
$ cargo run delivery.htb
    Finished dev [unoptimized + debuginfo] target(s) in 0.03s
     Running `target/debug/portscan delivery.htb`
Scanning delivery.htb - PortRange(1, 65535) - 500ms timeout..
Error: invalid IP address syntax
```
<br />
Ah, it's telling us that `delivery.htb` is not a valid IP address. I agree. Going back to Rust docs it looks like the trait [std::net::ToSocketAddrs](https://doc.rust-lang.org/std/net/trait.ToSocketAddrs.html#tymethod.to_socket_addrs) is exactly what we need to resolve it.

```rust
fn resolve_target(target: String) -> anyhow::Result<IpAddr> {
    match target.parse() {
        Ok(ip) => Ok(ip),
        Err(_) => {
            let fakesocketaddr = format!("{}:80", target);
            Ok(fakesocketaddr.to_socket_addrs()?.next().unwrap().ip())
        }
    }
}
```
<br />
Breakdown:
- If we successfully parsed the string to an `IpAddr` we are good.
- `to_socket_addrs` expect the string to be a socket address, i.e. have a port bound to it. Let's just do what it says and create a temp address with port 80.
- It also returns an Iterator on all the resolved addresses, we will cross our fingers and always take the first.

Running it again:
```shell
$ cargo run delivery.htb
    Compiling portscan v0.1.0 (/home/anon/portscan) 
     Finished dev [unoptimized + debuginfo] target(s) in 0.04s
      Running `target/debug/portscan delivery.htb`
Scanning 10.10.10.222 - PortRange(1, 65535) - 500ms timeout..

OPEN 22
OPEN 80
OPEN 8065
^C
cargo run delivery.htb  0.61s user 0.95s system 0% cpu 5:38.19 tota
```
<br />
Seems to work! Does is? Comparing it to nmap's result could be a good idea:

```shell
$ nmap -p- -sT delivery.htb
Starting Nmap 7.80 ( https://nmap.org ) at 2021-03-20 14:58 UTC
Nmap scan report for delivery.htb (10.10.10.222)
Host is up (0.015s latency).
Not shown: 65532 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8065/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 8.58 seconds
```
<br />
Nice! However, my portscanner is terribly slow compared to nmap. In fact, I got tired of waiting and ^C:d mine.
Iterating and scanning 65535 in a sequence takes some time. How about doing it in parallell?

```rust
const MAX_THREADS: usize = 3;

<snip>

fn start_thread(ip: IpAddr, ports: Vec<u16>, timeout: Duration) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        for port in ports {
            if knock(ip, port, timeout).is_ok() {
                println!("OPEN {}", port);
            }
        }
    })
}

fn main() -> anyhow::Result<()> {
    let opts: Opts = Opts::parse();

    let target_ip = resolve_target(opts.target)?;
    let ports = opts.ports.unwrap_or_else(PortRange::default);
    let timeout = Duration::from_millis(opts.timeout.unwrap_or(500));

    println!("Scanning {} - {}-{} - {}ms timeout..\n", target_ip, ports.0.first().unwrap(), ports.0.last().unwrap(), timeout.as_millis());

    if ports.0.len() < MAX_THREADS {
        for port in ports.0 {
            if knock(target_ip, port, timeout).is_ok() {
                println!("OPEN {}", port);
            }
        }
    } else {
        ports.0.chunks(MAX_THREADS)
            .map(|ports| start_thread(target_ip, ports.to_vec(), timeout))
            .collect::<Vec<JoinHandle<()>>>()
            .into_iter()
            .for_each(|h| h.join().unwrap());
    }

    Ok(())
}
```
<br />
```shell
$ time cargo run delivery.htb
   Compiling portscan v0.1.0 (/home/anon/portscan)
    Finished dev [unoptimized + debuginfo] target(s) in 1.99s
     Running `target/debug/portscan delivery.htb`
Scanning 10.10.10.222 - 1-65534 - 500ms timeout..

OPEN 22
OPEN 80
OPEN 8065
cargo run delivery.htb  1.95s user 0.49s system 94% cpu 2.571 total
```
<br />
Even faster than nmap! And also time for a reminder: **Everything I do here is extremely naive and stupid.** nmap probably includes a lot of fancy rate limiting and all that, for good reasons! Flooding a network like this is never good and will trigger even the stupidest firewall.

That concludes the portscanner. Hopefully we will have to revisit it and implement some sweet raw sockets for future boxes.

## Tool 2: HTTP Proxy

Now when we know that Delivery got ports 22, 80, 8065 open we can start doing some real work.

```shell
$ curl delivery.htb:8065
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=0"><meta name="robots" content="noindex, nofollow"><meta name="referrer" content="no-referrer"><title>Mattermost</title><meta name="mobile-web-app-capable" content="yes"><meta name="application-name" content="Mattermost"><meta name="format-detection" content="telephone=no"><link rel="icon" type="image/png" href="/static/images/favicon/favicon-default-16x16.png" sizes="16x16"><link rel="icon" type="image/png" href="/static/images/favicon/favicon-default-24x24.png" sizes="24x24"><link rel="icon" type="image/png" href="/static/images/favicon/favicon-default-32x32.png" sizes="32x32"><link rel="icon" type="image/png" href="/static/images/favicon/favicon-default-64x64.png" sizes="64x64"><link rel="icon" type="image/png" href="/static/images/favicon/favicon-default-96x96.png" sizes="96x96"><link rel="stylesheet" class="code_theme"><style>.error-screen{font-family:'Helvetica Neue',Helvetica,Arial,sans-serif;padding-top:50px;max-width:750px;font-size:14px;color:#333;margin:auto;display:none;line-height:1.5}.error-screen h2{font-size:30px;font-weight:400;line-height:1.2}.error-screen ul{padding-left:15px;line-height:1.7;margin-top:0;margin-bottom:10px}.error-screen hr{color:#ddd;margin-top:20px;margin-bottom:20px;border:0;border-top:1px solid #eee}.error-screen-visible{display:block}</style><meta http-equiv="Content-Security-Policy" content="script-src 'self' cdn.rudderlabs.com/ js.stripe.com/v3"><link href="/static/main.9ef911c6437f8b1ded00.css" rel="stylesheet"><script src="/static/main.ec4172de311a84144f07.js"></script><meta name="apple-mobile-web-app-title" content="Mattermost" /><meta name="apple-mobile-web-app-capable" content="yes" /><meta name="apple-mobile-web-app-status-bar-style" content="default" /><link rel="apple-touch-icon" sizes="76x76" href="/static/icon_76x76.png" /><link rel="apple-touch-icon" sizes="72x72" href="/static/icon_72x72.png" /><link rel="apple-touch-icon" sizes="60x60" href="/static/icon_60x60.png" /><link rel="apple-touch-icon" sizes="57x57" href="/static/icon_57x57.png" /><link rel="apple-touch-icon" sizes="152x152" href="/static/icon_152x152.png" /><link rel="apple-touch-icon" sizes="144x144" href="/static/icon_144x144.png" /><link rel="apple-touch-icon" sizes="120x120" href="/static/icon_120x120.png" /><link rel="manifest" href="/static/manifest.json" /></head><body class="font--open_sans enable-animations"><div id="root"><div class="error-screen"><h2>Cannot connect to Mattermost</h2><hr/><p>We're having trouble connecting to Mattermost. If refreshing this page (Ctrl+R or Command+R) does not work, please verify that your computer is connected to the internet.</p><br/></div><div class="loading-screen" style="position:relative"><div class="loading__content"><div class="round round-1"></div><div class="round round-2"></div><div class="round round-3"></div></div></div></div><div id="root-portal"></div><noscript>To use Mattermost, please enable JavaScript.</noscript></body></html>%
```
<br />
Hm.. For enumeration and exploring purposes it would be nice to render this in a browser.

Currently I'm accessing the HTB lab like this:

```
My machine <SSH> Headless Ubuntu VPS <VPN> HTB
```

Since my VPS is headless I'm gonna need to run the browser on my own machine, and to access the lab I need to create a HTTP proxy server running on my VPS.

Now you might be thinking: "ROFL this guy actually gonna access HTB on his own machine without any virtualization". That's correct. If anyone is sitting on a Firefox 0-day and decides to deploy it on a HTB box, please take all my files.

So, what's an HTTP proxy?  It's basically a HTTP client and a server at the same time right? [Hyper](https://crates.io/crates/hyper) seems like a hyped crate for this.

```rust
use hyper::{Client, Body, Request, Response, Server, Method, service::{make_service_fn, service_fn}};

async fn handle_request(req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
    match *req.method() {
        Method::CONNECT => {
            // Not supported
            Ok(Response::default())
        },
        _ => {
            let method = req.method().clone();
            let uri = req.uri().clone();
            let client = Client::new();
            let resp = client.request(req).await?;
            println!("{} {}\n\t -> {}", method, uri, resp.status());
            Ok(resp)
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let addr = ([0, 0, 0, 0], 666).into();
    let service = make_service_fn(|_| async { 
        Ok::<_, hyper::Error>(service_fn(handle_request)) 
    });

    let server = Server::bind(&addr).serve(service);
    println!("Listening on http://{}", addr);
    server.await?;

    Ok(())
}
```
<br />
That's it!

- HTTP server listing on port 666
- Forwards any request to the destination and returns the response
- For now, we are ignoring HTTPS (`CONNECT`), although we might need to implement that for future boxes.

Besides being pointless, we might actually make some use for this HTTP proxy by inspecting and modifying requests later.

## Hacking

After configuring Firefox to use HTTP proxy `[MY.VPS.IP]:666` and visiting `http://delivary.htb` we are presented with:

![](/1/2.png)

A lot of giveaways here:
- There's a helpdesk on `helpdesk.delivery.htb`, better put that in `/etc/hosts`.
- `delivery.htb:8065` is running a MatterMost server, whatever that is.
- We somehow need to get our hands on a `@delivty.htb` email address.

Starting with the helpdesk, it seems like we can create tickets as an unauthenticated user.
![](/1/h2.png)

Aha! Our ticket is assigned a `@delivery.htb` email address, perfect. However, when trying to view the ticket information by providing the email we used when creating the ticket and the ticker number, we get an error saying the email address is not verified.
![](/1/foo.png)

What if we create another ticket using the `@delivery.htb` email we received? Perhaps `*@delivery.htb` are verified by default?
![](/1/h3.png)
![](/1/h4.png)

Yep! So now we got access to a `@delivery.htb` email and can read its inbox. Using this we might be able to create a new account on the MatterMost server.

![](/1/h5.png)
![](/1/h6.png)
![](/1/m1.png)

We're in! And wow, they're really giving away information here. We can now login as the admin of the ticket system.
![](/1/m2.png)

After poking around for a while here without finding anything interesting (besides `somebloke` trying to upload a reverse shell `.exe`) I decided to try the same credentials for SSH.

![](/1/m4.png)
### User flag
![](/1/s1.png)

### Root flag

The `root` user in MatterMost chat mentioned something hashes and reusing passwords. Maybe we can find the hash for this user?

Some `find`'s later and I found the MatterMost installation and a configuration file:
![](/1/s2.png)

More hints! They are actually telling us what we need to do in the password to the database.
![](/1/s3.png)

And here is the hash for the root user, which according to the chat before should be a variation of `PleaseSubscribe!`.

### Tool 3: Hash bruteforce

Here I got extremely lucky and found the correct password by accident while testing the setup of my bruteforce script.

```rust
fn main() -> anyhow::Result<()> {
    let hash = "$2a$10$VM6EeymRxJ29r8Wjkr8Dtev0O.1STWb4.4ScG.anuu7v0EFJwgjjO";
    let known = "PleaseSubscribe!";
    
    for n in 0..=100 {
        let passwd = known.to_owned() + &n.to_string();
        if bcrypt::verify(&passwd, &hash).unwrap() {
            println!("PASSWORD: {}", passwd);
            return Ok(());
        }
    }
    
    Ok(())
}
```
<br />
```shell
$ cargo run
   Compiling hashcrack v0.1.0 (/home/anon/hashcrack)
    Finished dev [unoptimized + debuginfo] target(s) in 1.80s
     Running `target/debug/hashcrack`
PASSWORD: PleaseSubscribe!21
```
<br />
Oh well. Maybe next time we'll need to come back here and generate some fancy permutations and stuff. Logging in with `root:PleaseSubscribe!21` gives us the root flag.

## End

That was pretty easy. Hopefully next box will require us to write some custom exploits.

