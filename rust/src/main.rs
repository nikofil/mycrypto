// RC4 bias attack
extern crate crypto;
extern crate rand;
extern crate base64;

use std::thread;
use crypto::symmetriccipher::SynchronousStreamCipher;
use crypto::rc4;
use rand::{Rng, OsRng};

fn main() {
    let mut handles = Vec::new();

    let secret = base64::decode("QkUgU1VSRSBUTyBEUklOSyBZT1VSIE9WQUxUSU5F").unwrap();
    let mut req = vec!['/' as u8; 16];
    req.extend_from_slice(&secret);
    let req = req;

    for i in 0..secret.len()+1 {
        let req2 = req.clone();
        let handle = thread::spawn(move || {
            let mut rng = OsRng::new().unwrap();
            let mut key: [u8; 16] = [0;16];
            let mut enc: [u8; 16] = [0;16];
            let mut counts: [u32; 256] = [0; 256];
            for _ in 0..(1 << 24) {
                rng.fill_bytes(&mut key);
                let mut ciph = rc4::Rc4::new(&key);
                ciph.process(&req2[i..i+16], &mut enc);
                counts[enc[15] as usize] += 1;
            }
            let max = counts.iter().enumerate().fold((0 as usize, 0 as u32), {
                |(i, v), (ni, nv)| if v > *nv {(i, v)} else {(ni, *nv)}
            });
            let ret = (max.0^0xF0) as u8 as char;
            //println!("idx {} val {}", i, ret);
            ret
        });
        handles.push(handle);
    }
    for h in handles {
        print!("{}", h.join().unwrap() as char);
    }
    println!();
}
