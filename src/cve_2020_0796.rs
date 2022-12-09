use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

use crate::utils::contains;

const REQUEST: [u8; 196] = [
    0, 0, 0, 192, 254, 83, 77, 66, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 31, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 36, 0, 8, 0, 1, 0, 0, 0, 127, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 120, 0, 0, 0,
    2, 0, 0, 0, 2, 2, 16, 2, 34, 2, 36, 2, 0, 3, 2, 3, 16, 3, 17, 3, 0, 0, 0, 0, 1, 0, 38, 0, 0, 0, 0, 0, 1,
    0, 32, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 3, 0, 14, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0,
];

const PUBLIC: [u8; 6] = [80, 117, 98, 108, 105, 99];

pub async fn run(ip: &str) {
    let mut conn = TcpStream::connect(ip).await.unwrap();
    conn.write_all(&REQUEST).await.unwrap();
    let mut buf = vec![0; 1024];
    let n = conn.read(&mut buf).await.unwrap();
    if contains(&buf[..n], &PUBLIC) == true {
        println!("{ip} 存在 CVE-2020-0796 漏洞")
    }
}
