use std::sync::mpsc::Sender;
use std::thread;
use std::io::{self, Write};
use std::{str::FromStr, sync::mpsc::channel};
use std::net::{IpAddr, TcpStream};
use clap:: {
    Args, Parser, Subcommand
};

const MAX:u16 = 65535;

#[derive(Debug, Parser)]
#[clap(author, version, about)]
pub struct IpSniffer {
    #[clap(subcommand)]
    pub ip_snif: IpSnifSubCmd,
}

#[derive(Subcommand, Debug)]
pub enum IpSnifSubCmd {
    WithThreads(WithThreadsCommand),
    Default(DefaultCommand),
}

#[derive(Args, Debug)]
pub struct WithThreadsCommand{
    ///number of threads
    #[clap(value_parser)]
    pub j: String,

    ///Ip Address to be passed
    #[clap(value_parser)]
    pub ip_address: String,
}

#[derive(Args, Debug)]
pub struct DefaultCommand {
    ///Ip Address to be passed
    #[clap(value_parser)]
    pub ip_address: String,
}

pub fn scan(tx: Sender<u16>, start_port: u16, addr: IpAddr, num_threads: u16){
    let mut port =  start_port + 1;
    loop {
        match TcpStream::connect((addr, port)){
            Ok(_) =>{ 
                print!(".");
                io::stdout().flush().unwrap();
                tx.send(port).unwrap();
        },
            Err(_) => {},
        }

        if (MAX- port) <= num_threads{
            break;
        }
        port += num_threads;
    }
}

fn main() {
    let cli = IpSniffer::parse();

    match  &cli.ip_snif {
        IpSnifSubCmd::WithThreads(args) =>{
            let number_of_threads = &args.j.parse::<u16>().unwrap();
            let ip_address = IpAddr::from_str(&args.ip_address);
            let ip_addr = ip_address.unwrap();

            let num_threads = number_of_threads.clone();
            let (tx, rx) = channel();

            for i in 0..num_threads{
                let tx = tx.clone();

                thread::spawn(move || {
                    scan(tx, i, ip_addr, num_threads)
                });
            }

            let mut out = vec![];
            drop(tx);
            for p in rx {
                out.push(p);
            }

            println!("");
            out.sort();
            for v in out {
                println!("{} is open", v);
            }
        
        
        }
        IpSnifSubCmd::Default(args) => {
            let ip_address = IpAddr::from_str(&args.ip_address);
            let ip_addr = ip_address.unwrap();

            let num_threads = 500;

            let (tx, rx) = channel();

            for i in 0..num_threads {
                let tx = tx.clone();
                 
                thread::spawn(move ||{
                    scan(tx, i, ip_addr, num_threads);
                });
            }

            let mut out:Vec<u16> = Vec::new();

            drop(tx);

            for p in rx{
                out.push(p);
            }

            println!("");
            out.sort();
            for v in out {
                println!("{} is open", v);
            }

    
        }
    }
}
