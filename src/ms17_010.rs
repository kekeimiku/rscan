use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

const NEGOTIATE_PROTOCOL: [u8; 137] = [
    0, 0, 0, 133, 255, 83, 77, 66, 114, 0, 0, 0, 0, 24, 83, 192, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    255, 254, 0, 0, 64, 0, 0, 98, 0, 2, 80, 67, 32, 78, 69, 84, 87, 79, 82, 75, 32, 80, 82, 79, 71, 82, 65,
    77, 32, 49, 46, 48, 0, 2, 76, 65, 78, 77, 65, 78, 49, 46, 48, 0, 2, 87, 105, 110, 100, 111, 119, 115, 32,
    102, 111, 114, 32, 87, 111, 114, 107, 103, 114, 111, 117, 112, 115, 32, 51, 46, 49, 97, 0, 2, 76, 77, 49,
    46, 50, 88, 48, 48, 50, 0, 2, 76, 65, 78, 77, 65, 78, 50, 46, 49, 0, 2, 78, 84, 32, 76, 77, 32, 48, 46,
    49, 50, 0,
];
const SESSION_SETUP: [u8; 140] = [
    0, 0, 0, 136, 255, 83, 77, 66, 115, 0, 0, 0, 0, 24, 7, 192, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    255, 254, 0, 0, 64, 0, 13, 255, 0, 136, 0, 4, 17, 10, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 212,
    0, 0, 0, 75, 0, 0, 0, 0, 0, 0, 87, 0, 105, 0, 110, 0, 100, 0, 111, 0, 119, 0, 115, 0, 32, 0, 50, 0, 48,
    0, 48, 0, 48, 0, 32, 0, 50, 0, 49, 0, 57, 0, 53, 0, 0, 0, 87, 0, 105, 0, 110, 0, 100, 0, 111, 0, 119, 0,
    115, 0, 32, 0, 50, 0, 48, 0, 48, 0, 48, 0, 32, 0, 53, 0, 46, 0, 48, 0, 0, 0,
];

pub async fn run(ip: &str) -> std::io::Result<()> {
    let mut conn = TcpStream::connect(ip).await?;

    let mut tree_connect = [
        0, 0, 0, 96, 255, 83, 77, 66, 117, 0, 0, 0, 0, 24, 7, 192, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        255, 254, 0, 8, 64, 0, 4, 255, 0, 96, 0, 8, 0, 1, 0, 53, 0, 0, 92, 0, 92, 0, 49, 0, 57, 0, 50, 0, 46,
        0, 49, 0, 54, 0, 56, 0, 46, 0, 49, 0, 55, 0, 53, 0, 46, 0, 49, 0, 50, 0, 56, 0, 92, 0, 73, 0, 80, 0,
        67, 0, 36, 0, 0, 0, 63, 63, 63, 63, 63, 0,
    ];
    let mut trans_named_pipe = [
        0, 0, 0, 74, 255, 83, 77, 66, 37, 0, 0, 0, 0, 24, 1, 40, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8,
        142, 163, 1, 8, 82, 152, 16, 0, 0, 0, 0, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 74,
        0, 0, 0, 74, 0, 2, 0, 35, 0, 0, 0, 7, 0, 92, 80, 73, 80, 69, 92, 0,
    ];
    let mut trans2_session_setup = [
        0, 0, 0, 78, 255, 83, 77, 66, 50, 0, 0, 0, 0, 24, 7, 192, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8,
        255, 254, 0, 8, 65, 0, 15, 12, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 166, 217, 164, 0, 0, 0, 12, 0, 66, 0,
        0, 0, 78, 0, 1, 0, 14, 0, 13, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];

    conn.write_all(&NEGOTIATE_PROTOCOL).await?;
    let mut reply = vec![0; 1024];
    let size = conn.read(&mut reply).await?;
    if size < 36 || u32::from_le_bytes(reply[9..13].try_into().unwrap()) != 0 {
        println!("no");
        return Ok(());
    }

    conn.write_all(&SESSION_SETUP).await?;
    let size = conn.read(&mut reply).await?;
    if size < 36 {
        println!("no");
        return Ok(());
    }
    if u32::from_le_bytes(reply[9..13].try_into().unwrap()) != 0 {
        println!("can't determine whether {ip} is vulnerable or not\n");
        return Ok(());
    }

    let session_setup_response = &reply[36..size];

    let mut os = vec![];

    if session_setup_response[0] != 0 {
        let byte_count = u16::from_le_bytes(session_setup_response[7..9].try_into().unwrap());
        if size != byte_count as usize + 45 {
            println!("invalid session setup AndX response");
            return Ok(());
        } else {
            for i in 10..session_setup_response.len() - 1 {
                if session_setup_response[i] == 0 && session_setup_response[i + 1] == 0 {
                    os = session_setup_response[10..i].to_vec();
                    break;
                }
            }
        }
    }

    let user_id: [u8; 2] = reply[32..34].try_into().unwrap();
    tree_connect[32] = user_id[0];
    tree_connect[33] = user_id[1];

    conn.write_all(&tree_connect).await?;
    let size = conn.read(&mut reply).await?;
    if size < 36 {
        return Ok(());
    }

    let tree_id: [u8; 2] = reply[28..30].try_into().unwrap();
    trans_named_pipe[28] = tree_id[0];
    trans_named_pipe[29] = tree_id[1];
    trans_named_pipe[32] = user_id[0];
    trans_named_pipe[33] = user_id[1];

    conn.write_all(&trans_named_pipe).await?;
    let size = conn.read(&mut reply).await?;
    if size < 36 {
        return Ok(());
    }

    if reply[9..13] == [0x05, 0x02, 0x00, 0xc0] {
        println!("{ip} {} 存在 MS17-010 漏洞", String::from_utf8_lossy(&os));

        // detect present of DOUBLEPULSAR SMB implant
        trans2_session_setup[28] = tree_id[0];
        trans2_session_setup[29] = tree_id[1];
        trans2_session_setup[32] = user_id[0];
        trans2_session_setup[33] = user_id[1];
        conn.write_all(&trans2_session_setup).await?;

        let size = conn.read(&mut reply).await?;
        if size < 36 {
            return Ok(());
        }

        if reply[34] == 0x51 {
            println!("DOUBLEPULSAR SMB IMPLANT in {ip}");
        }
    } else {
        println!("safety")
    }

    Ok(())
}
