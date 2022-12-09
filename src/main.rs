use rscan::{cve_2020_0796, ms17_010};
use tokio::time;

#[tokio::main]
async fn main() {
    let list = vec![
        "192.168.31.30:445", // win7 vm
        "192.168.31.31:445",
        "192.168.31.196:445", //mypc
        "192.168.31.241:445", //win10 vm
    ];

    let duration = tokio::time::Duration::from_secs(1);

    let handles = list
        .iter()
        .map(|ip| tokio::spawn(time::timeout(duration, ms17_010::run(ip))))
        .collect::<Vec<_>>();

    for h in handles {
        println!("{:?}", h.await);
    }

    let handles = list
        .iter()
        .map(|ip| tokio::spawn(time::timeout(duration, cve_2020_0796::run(ip))))
        .collect::<Vec<_>>();

    for h in handles {
        println!("{:?}", h.await);
    }
}
