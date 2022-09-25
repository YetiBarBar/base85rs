# base85rs
A library to encode and decode Base85 [RFC1924 variant](https://datatracker.ietf.org/doc/html/rfc1924)

# Description
This is only one variant of Base85, not the most common one (ASCII-85 and Z85 are wider spread). This
variant will most likely been seen in CTF challenges.

During decoding, whitespaces are ignored.

# Usage
To encode data:
```
let data = [b'a'];
let encoded = base85rs::encode(&data);
assert_eq!(encoded, "VE");
```

To decode data:
```
let data = "VE";
let decoded = base85rs::decode(&data);
assert_eq!(decoded, Some(vec![b'a']));
```
