use std::io::prelude::*;
use std::net::{SocketAddr, TcpStream};
use std::str;
use std::time::Duration;
use regex::Regex;
use tns_packets::*;
use env_logger;
use log;
use clap::{Command, Arg};

fn read_data(stream: &mut TcpStream) -> Result<String, String> {
    let mut data_packets: Vec<TnsDataPacket> = Vec::new();

    while data_packets.len() == 0 || !data_packets.get(data_packets.len() - 1).unwrap().is_end_of_data() {
        /* Read and process packet header */
        let mut buf = [0x00; 8];
        stream.read_exact(&mut buf).expect("Failed reading data packet header!");
        let header = TnsPacketHeader::new(buf);

        /* Check that received packet is a DATA packet and return error if not */
        match header.get_packet_type() {
            Ok(pt) => if pt != TnsPacketType::DATA {
                return Err(format!("Unexpected packet type! Expected DATA, got {:?}", pt));
            },
            Err(e) => return Err(format!("Unknown packet type! Expected 6, got {}", e)),
        };

        /* Read packet body and add data packet to collection */
        let data_length = header.get_packet_length() - 8;
        let mut buf = vec![0x00; data_length as usize];
        stream.read(&mut buf).expect("Failed reading data packet body!");
        let data_packet = TnsDataPacket::new(&buf);
        match data_packet {
            Ok(dp) => {
                log::debug!("{:?}", dp);
                data_packets.push(dp);
            },
            Err(_) => return Err(format!("Something went wrong creating a data packet out of {:?}", buf)),
        };
    }

    let mut res = String::new();
    for p in data_packets {
        let data = match p.get_data_as_str() {
            Ok(s) => s,
            Err(_) => {
                return Err(format!("Non-UTF8 char in response. Raw bytes:\n{:?}", p.get_data()));
            },
        };
        res.push_str(data);
    }

    Ok(res)
}

fn send_command(command: &str, args: &str, target: SocketAddr, client_ver: &str) {
    let ver = match client_ver {
        "8g" => "135294976",
        "9i" => "153092352",
        "10g" => "169870336",
        "11g" => "185599744",
        _ => "318767104",
    };
    let connect_data = format!("(DESCRIPTION=(CONNECT_DATA=(CID=(PROGRAM=)(HOST=localhost.localdomain)(USER=oracle))(COMMAND={})(ARGUMENTS=4)(SERVICE=LISTENER)(VERSION={}){}))", command, ver, args);

    let connect_packet = match TnsConnectPacket::new(connect_data, client_ver) {
        Ok(pkt) => pkt,
        Err(e) => { eprintln!("{}", e); return; }
    };
    let connect_bytes = connect_packet.as_bytes();

    /* Establish TCP connection to target with 5 second timeout */
    let mut stream = TcpStream::connect(target).expect("Failed to connect to server!");
    stream.set_read_timeout(Some(Duration::new(5, 0))).unwrap();

    /* Send the TNS connect packet to target */
    stream.write(&connect_bytes).expect("Failed sending packet to server!");

    /* Read initial response packet header - should be ACCEPT or REFUSE(?) */
    let mut buf: [u8; 8] = [0x00; 8];
    stream.read(&mut buf).expect("Failed reading packet header!");
    let header = TnsPacketHeader::new(buf);

    /* Read total packet length from header and subtract header length to get remaining number of bytes,
    then read rest of packet */
    let packet_len_without_header = (header.get_packet_length() - 8) as usize;
    let mut buf: Vec<u8> = vec![0x00; packet_len_without_header];
    stream.read(&mut buf).expect("Failed reading packet body!");

    /* Handle packet body different depending on packet type specified in header */
    match header.get_packet_type() {
        Ok(TnsPacketType::ACCEPT) => {
            /* Accept packets have a small data section which may or may not be empty:
             In response to a VERSION command -> will contain VSSNUM e.g. (DESCRIPTION=(TMP=)(VSNNUM=135294976)(ERR=0)) */
            let accept_packet = TnsAcceptPacket::new(&buf);
            if command.to_lowercase() == "version" {
                let accept_data = match accept_packet.get_data_as_str() {
                    Ok(data) => data,
                    Err(_) => {
                        eprintln!("Non-UTF8 char in response. Raw bytes:\n{:?}", accept_packet.get_data());
                        return;
                    },
                };
                println!("{}", accept_data);
            }

            /* Accept packets should be followed by data packets containing the response data we want.
             Pass ownership of the tcpstream to data packet specialist function */
            let response_data = match read_data(&mut stream) {
                Ok(data) => data,
                Err(e) => { eprintln!("{}", e); return; }
            };

            /* Print response data */
            println!("{}", response_data);
        },
        Ok(TnsPacketType::REFUSE) => {
            /* Refuse packets occur in multiple instances:
             1. In response to a command where the return data is small enough to not warrant a data packet e.g
                - PING  ->  (DESCRIPTION=(TMP=)(VSNNUM=135294976)(ERR=0)(ALIAS=LISTENER))
                - log_file  ->  (DESCRIPTION=(TMP=)(VSNNUM=135294976)(ERR=0)(COMMAND=log_file)(LOGFILENAME=listener.log))
             2. When authorisation is denied to run the sent command, or when the command is invalid -> will contain error message  e.g. (DESCRIPTION=(TMP=)(VSNNUM=169869568)(ERR=1189)(ERROR_STACK=(ERROR=(CODE=1189)(EMFI=4)))) */
            let refuse_packet = TnsRefusePacket::new(&buf);
            let refuse_data = match refuse_packet.get_data_as_str() {
                Ok(data) => data,
                Err(_) => {
                    eprintln!("Non-UTF8 char in response. Raw bytes:\n{:?}", refuse_packet.get_data());
                    return;
                },
            };
            println!("{}", refuse_data);
            
            /* Get VSSNUM if present in response data */
            match get_vsnnum(refuse_data) {
                Some(vsnnum) => println!("VSNNUM: {}, -> {:x?}", vsnnum, vsnnum),
                None => return,
            };
        }
        Ok(_) => (),
        Err(e) => eprintln!("{}", e),
    };
}

fn get_vsnnum(data: &str) -> Option<u32> {
    let re = Regex::new(r"VSNNUM=\d*\){1}").unwrap();
    let vsnnum = match re.find(data) {
        Some(m) => m.as_str().trim_start_matches("VSNNUM=").trim_end_matches(")"),
        None => return None,
    };
    Some(vsnnum.parse::<u32>().unwrap())
}

fn main() {
    env_logger::init();
    let arg_matches = Command::new("TnsTool")
        .version("0.1")
        .author("rewks")
        .about("A tool to run user specified commands against a target Oracle TNS Listener service")
        .arg(Arg::new("target").short('t').long("target").help("Target hostname/IP").required(true))
        .arg(Arg::new("port").short('p').long("port").default_value("1521").value_parser(clap::value_parser!(u16)).help("Port of TNS listener"))
        .arg(Arg::new("command").short('c').long("cmd").default_value("PING").help("Command to send to remote host"))
        .arg(Arg::new("args").long("args").help("Arguments to send with command"))
        .arg(Arg::new("client_version").long("client_version").default_value("19c").help("Version of lsnrctl client to emulate"))
        .get_matches();

    /* Parse args into variables */
    let target_addr = arg_matches.get_one::<String>("target").unwrap();
    let target_port = arg_matches.get_one::<u16>("port").unwrap();
    let cmd = arg_matches.get_one::<String>("command").unwrap();
    let raw_args = arg_matches.get_many::<String>("args");
    let client_version = arg_matches.get_one::<String>("client_version").unwrap();
    let mut args = String::new();

    match raw_args {
        Some(values) => {
            for a in values.into_iter() {
                let formatted_arg = format!("(VALUE={})", a);
                args.push_str(&formatted_arg);
            }
        },
        None => (),
    }

    /* Combine given host/IP and port into a SocketAddr */
    let target_combined_addr = format!("{}:{}", target_addr, target_port);
    let target_socket_addr = target_combined_addr.parse::<SocketAddr>().expect("Invalid target address");
    
    send_command(cmd, &args, target_socket_addr, client_version);

}