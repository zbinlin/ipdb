use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use serde_json as json;
use std::io::{
    self,
    Seek,
    SeekFrom,
    prelude::*,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::convert::TryInto;
use std::str::FromStr;
use std::cell::RefCell;

#[allow(non_camel_case_types)]
#[cfg_attr(test, derive(Debug))]
#[derive(Copy, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub enum Fields {
    country_name,
    region_name,
    city_name,
}

type Info = HashMap<Fields, String>;

#[allow(non_camel_case_types)]
#[cfg_attr(test, derive(Debug))]
#[derive(Copy, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub enum Language {
    CN,
}
type Languages = HashMap<Language, u8>;

#[cfg_attr(test, derive(Debug, PartialEq))]
#[derive(Serialize, Deserialize)]
pub struct Header {
    build: u32,
    ip_version: u8,
    languages: Languages,
    node_count: u32,
    total_size: u32,
    fields: Vec<Fields>,
}

impl Header {
    pub fn new<T: Seek + Read>(cursor: &mut T) -> io::Result<Header> {
        cursor.seek(SeekFrom::Start(0))?;
        let mut buf = [0; 4];
        let n = cursor.read(&mut buf)?;
        assert_eq!(n, buf.len());

        let size = u32::from_be_bytes(buf);
        let size = size as usize;
        cursor.seek(SeekFrom::Start(4))?;
        let mut buf = vec![0; size];
        let n = cursor.read(&mut buf)?;
        assert_eq!(n, size);

        let json_str = String::from_utf8_lossy(&buf);
        let result: Header = json::from_str(&json_str)?;
        Ok(result)
    }
}

#[cfg_attr(test, derive(Debug, PartialEq))]
enum Leaf {
    Left = 0,
    Right = 1,
}

type Node = Option<u32>;

pub struct Nodes {
    contents: Vec<u8>,
    node_count: u32,
    offset: u64,
    max_offset: u32,
    ipv4_offset: Option<u32>,
}

impl Nodes {
    pub fn new<T>(cursor: &mut T) -> io::Result<Self> where T: Seek + Read {
        cursor.seek(SeekFrom::Start(0))?;
        let mut buf = [0; 4];
        let n = cursor.read(&mut buf)?;
        assert_eq!(n, buf.len());

        let size = u32::from_be_bytes(buf);

        let headers = Header::new(cursor)?;

        let start = size as u64 + 4;
        let size = headers.node_count as usize * 8;
        let mut contents = vec![0; size];
        cursor.seek(SeekFrom::Start(start))?;
        let n = cursor.read(&mut contents)?;
        assert_eq!(n, size);

        Ok(Self {
            contents,
            offset: start,
            node_count: headers.node_count,
            max_offset: headers.total_size,
            ipv4_offset: None,
        })
    }

    fn find_node(&self, node: u32, leaf: Leaf) -> Node {
        if node > self.node_count {
            return Some(node);
        }

        let idx = node as usize * 8;
        let buf = match leaf {
            Leaf::Left => {
                let left = self.contents[idx..idx+4].try_into();
                if let Err(e) = left {
                    eprintln!("Find left node error: {}", e);
                    return None;
                } else {
                    left.unwrap()
                }
            },
            Leaf::Right => {
                let right = self.contents[idx+4..idx+8].try_into();
                if let Err(e) = right {
                    eprintln!("Find right node error: {}", e);
                    return None;
                } else {
                    right.unwrap()
                }
            },
        };

        Some(u32::from_be_bytes(buf))
    }

    fn get_ipv4_offset(&self) -> u32 {
        if let Some(offset) = self.ipv4_offset {
            return offset;
        }

        let mut node = 0u32;
        for _ in 0..80 {
            node = self.find_node(node, Leaf::Left).unwrap_or(0u32);
        }
        for _ in 80..96 {
            node = self.find_node(node, Leaf::Right).unwrap_or(0u32);
        }
        node
    }

    fn ip_to_leafs(ip: &IpAddr) -> Vec<Leaf> {
        let ip_iter = match ip {
            IpAddr::V4(ip) => ip.octets().to_vec(),
            IpAddr::V6(ip) => ip.octets().to_vec(),
        };
        ip_iter.iter().map(|o| {
            (0..8).rev().map(move |bit| {
                ((o >> bit) as u8) & 0b0000_0001_u8
            }).map(|val| {
                match val {
                    0 => Leaf::Left,
                    1 => Leaf::Right,
                    _ => panic!("Never run here!"),
                }
            })
        }).flatten().collect()
    }

    pub fn find(&self, ip: IpAddr) -> Node {
        if ip.is_loopback() || ip.is_multicast() || ip.is_unspecified() {
            return None;
        }
        let mut node = match ip {
            IpAddr::V4(_) => self.get_ipv4_offset(),
            IpAddr::V6(_) => 0u32,
        };
        let leafs = Self::ip_to_leafs(&ip);
        for leaf in leafs {
            if let Some(n) = self.find_node(node, leaf) {
                if n > self.node_count {
                    return Some(n);
                }
                node = n;
            } else {
                return None;
            }
        }
        Some(node)
    }

    fn find_next(&self, ip_map: &mut HashMap<u32, (String, String)>, ips: Vec<u8>, next: u32) {
        if next >= self.node_count {
            if ips.len() > 128 || (next - self.node_count + self.node_count * 8) > self.max_offset {
                return;
            }
            let ips_start: u128 = ips.iter().enumerate().fold(0u128, |ip, (k, v)| {
                ip | ((*v as u128) << (127 - k))
            });
            let ip_start = Ipv6Addr::from(ips_start);
            let ip_start = if let Some(ip_start) = ip_start.to_ipv4() {
                ip_start.to_string()
            } else {
                ip_start.to_string()
            };
            let ips_end: u128 = [ips.clone(), vec![1; 128 - ips.len()]].concat()
                .iter().enumerate().fold(0u128, |ip, (k, v)| {
                ip | ((*v as u128) << (127 - k))
            });
            let ip_end = Ipv6Addr::from(ips_end);
            let ip_end = if let Some(ip_end) = ip_end.to_ipv4() {
                ip_end.to_string()
            } else {
                ip_end.to_string()
            };
            ip_map.insert(next, (ip_start, ip_end));
            return;
        }

        let start = next as usize * 8;
        let left = u32::from_be_bytes(self.contents[start..start+4].try_into().unwrap());
        let right = u32::from_be_bytes(self.contents[start+4..start+8].try_into().unwrap());

        self.find_next(ip_map, [ips.clone(), vec![0u8]].concat(), left);
        self.find_next(ip_map, [ips, vec![1u8]].concat(), right);
    }

    pub fn reverse(&self) -> HashMap<u32, (String, String)> {
        let mut map = HashMap::new();
        self.find_next(&mut map, vec![], 0u32);
        map
    }
}

pub struct Ipdb<'a, T: 'a + Seek + Read> {
    cursor: RefCell<&'a mut T>,
    pub header: Header,
    pub nodes: Nodes,
}

impl<'a, T: 'a + Seek + Read> Ipdb<'a, T> {
    pub fn new(cursor: &'a mut T) -> Self {
        let header = {
            Header::new(cursor).unwrap()
        };
        let nodes = {
            Nodes::new(cursor).unwrap()
        };
        Self {
            cursor: RefCell::new(cursor),
            header,
            nodes,
        }
    }

    fn resolve(&self, node: Node, language: Language) -> Option<Info> {
        let node = node? as u64;

        let node_count = self.header.node_count as u64;
        let idx = self.nodes.offset + node - node_count + node_count * 8;

        if let Err(e) = self.cursor.borrow_mut().seek(SeekFrom::Start(idx)) {
            eprintln!("[Resolve({})]: Seek to start failure: {}", node, e);
            return None;
        }

        let mut buf = [0u8; 2];
        let n = self.cursor.borrow_mut().read(&mut buf).unwrap();
        if n != 2 {
            eprintln!("[Resolve({})]: Read size at {}, expect read {}, actual read {}", node, idx, 2, n);
            return None;
        }

        let size = u16::from_be_bytes(buf) as usize;

        if size == 0 {
            let mut info = Info::new();
            info.insert(Fields::country_name, "".to_string());
            info.insert(Fields::region_name, "".to_string());
            info.insert(Fields::city_name, "".to_string());
            return Some(info);
        }

        let mut buf = vec![0u8; size];
        let n = self.cursor.borrow_mut().read(&mut buf).unwrap();
        if n != size {
            eprintln!("[Resolve({})]: Read contents at {}, expect read {}, actual read {}", node, idx, size, n);
            return None;
        }

        let data = String::from_utf8_lossy(&buf);

        let data: Vec<_> = data.split('\t').collect();

        let fields = &self.header.fields;
        let lang_idx = self.header.languages.get(&language)?;
        let start = *lang_idx as usize * fields.len();
        let end = start + fields.len();
        assert!(data.len() >= end, "[Resolve({})]: data.len(): {} >= end: {}, data is {:?}", node, data.len(), end, data);
        let data = &data[start..end];

        Some(fields.iter().zip(data).map(|(key, val)| {
            (*key, (*val).to_owned())
        }).collect())
    }

    pub fn find(&self, ip: &str, language: Language) -> Option<Info> {
        let ip = if let Ok(ip) = Ipv6Addr::from_str(ip) {
            IpAddr::V6(ip)
        } else if let Ok(ip) = Ipv4Addr::from_str(ip) {
            IpAddr::V4(ip)
        } else {
            return None;
        };

        self.resolve(self.nodes.find(ip), language)
    }

    pub fn reverse(&self, language: Language) -> HashMap<(String, String), Info> {
        let hash = self.nodes.reverse();

        hash.iter().map(move |(node, ip)| {
            (ip.clone(), self.resolve(Some(*node), language).unwrap_or_else(|| panic!("{}", node)))
        }).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_works() {
        let data = r#"
            {
                "build": 1562137969,
                "ip_version": 1,
                "languages": {
                    "CN": 0
                },
                "node_count": 451190,
                "total_size": 3649744,
                "fields": [
                    "country_name",
                    "region_name",
                    "city_name"
                ]
            }
        "#;
        let v: Header = json::from_str(data).unwrap();
        assert_eq!(v, Header {
            build: 1_562_137_969u32,
            ip_version: 1,
            languages: vec![
                (Language::CN, 0),
            ].into_iter().collect(),
            node_count: 451_190_u32,
            total_size: 3_649_744_u32,
            fields: vec![
                Fields::country_name,
                Fields::region_name,
                Fields::city_name,
            ],
        });
    }

    #[test]
    fn new_header_works() {
        use std::io::Cursor;
        use hex::FromHex;

        let data = Vec::from_hex("\
            000000957b226275696c64223a313536323133373936392c2269705f76657273\
            696f6e223a312c226c616e677561676573223a7b22434e223a307d2c226e6f64\
            655f636f756e74223a3435313139302c22746f74616c5f73697a65223a333634\
            393734342c226669656c6473223a5b22636f756e7472795f6e616d65222c2272\
            6567696f6e5f6e616d65222c22636974795f6e616d65225d7d000000010006e2\
            76000000020006e276000000030006e276000000040006e276000000050006e2\
        ").unwrap();
        let mut reader = Cursor::new(data);
        let result = Header::new(&mut reader).unwrap();
        assert_eq!(result, Header {
            build: 1_562_137_969u32,
            ip_version: 1,
            languages: vec![
                (Language::CN, 0),
            ].into_iter().collect(),
            node_count: 451_190_u32,
            total_size: 3_649_744_u32,
            fields: vec![
                Fields::country_name,
                Fields::region_name,
                Fields::city_name,
            ],
        });
    }

    #[test]
    fn test_node_ip_to_leafs_ipv4() {
        assert_eq!(
            Nodes::ip_to_leafs(&IpAddr::V4(Ipv4Addr::from_str("1.2.3.4").unwrap())),
            vec![
                Leaf::Left, Leaf::Left, Leaf::Left, Leaf::Left, Leaf::Left, Leaf::Left, Leaf::Left, Leaf::Right,
                Leaf::Left, Leaf::Left, Leaf::Left, Leaf::Left, Leaf::Left, Leaf::Left, Leaf::Right, Leaf::Left,
                Leaf::Left, Leaf::Left, Leaf::Left, Leaf::Left, Leaf::Left, Leaf::Left, Leaf::Right, Leaf::Right,
                Leaf::Left, Leaf::Left, Leaf::Left, Leaf::Left, Leaf::Left, Leaf::Right, Leaf::Left, Leaf::Left,
            ],
        );
    }

    #[test]
    fn test_node_ip_to_leafs_ipv6() {
        assert_eq!(
            Nodes::ip_to_leafs(&IpAddr::V6(Ipv6Addr::from_str("f0f0:1:2:3:4:5:6:7").unwrap())),
            vec![
                Leaf::Right, Leaf::Right, Leaf::Right, Leaf::Right, Leaf::Left, Leaf::Left, Leaf::Left, Leaf::Left,
                Leaf::Right, Leaf::Right, Leaf::Right, Leaf::Right, Leaf::Left, Leaf::Left, Leaf::Left, Leaf::Left,
                Leaf::Left, Leaf::Left, Leaf::Left, Leaf::Left, Leaf::Left, Leaf::Left, Leaf::Left, Leaf::Left,
                Leaf::Left, Leaf::Left, Leaf::Left, Leaf::Left, Leaf::Left, Leaf::Left, Leaf::Left, Leaf::Right,
                Leaf::Left, Leaf::Left, Leaf::Left, Leaf::Left, Leaf::Left, Leaf::Left, Leaf::Left, Leaf::Left,
                Leaf::Left, Leaf::Left, Leaf::Left, Leaf::Left, Leaf::Left, Leaf::Left, Leaf::Right, Leaf::Left,
                Leaf::Left, Leaf::Left, Leaf::Left, Leaf::Left, Leaf::Left, Leaf::Left, Leaf::Left, Leaf::Left,
                Leaf::Left, Leaf::Left, Leaf::Left, Leaf::Left, Leaf::Left, Leaf::Left, Leaf::Right, Leaf::Right,
                Leaf::Left, Leaf::Left, Leaf::Left, Leaf::Left, Leaf::Left, Leaf::Left, Leaf::Left, Leaf::Left,
                Leaf::Left, Leaf::Left, Leaf::Left, Leaf::Left, Leaf::Left, Leaf::Right, Leaf::Left, Leaf::Left,
                Leaf::Left, Leaf::Left, Leaf::Left, Leaf::Left, Leaf::Left, Leaf::Left, Leaf::Left, Leaf::Left,
                Leaf::Left, Leaf::Left, Leaf::Left, Leaf::Left, Leaf::Left, Leaf::Right, Leaf::Left, Leaf::Right,
                Leaf::Left, Leaf::Left, Leaf::Left, Leaf::Left, Leaf::Left, Leaf::Left, Leaf::Left, Leaf::Left,
                Leaf::Left, Leaf::Left, Leaf::Left, Leaf::Left, Leaf::Left, Leaf::Right, Leaf::Right, Leaf::Left,
                Leaf::Left, Leaf::Left, Leaf::Left, Leaf::Left, Leaf::Left, Leaf::Left, Leaf::Left, Leaf::Left,
                Leaf::Left, Leaf::Left, Leaf::Left, Leaf::Left, Leaf::Left, Leaf::Right, Leaf::Right, Leaf::Right,
            ],
        );
    }
}
