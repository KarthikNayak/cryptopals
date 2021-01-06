# cryptopals
Solving the matasano challenge, while timing myself doing it! 

Do note that some of these were solved by me around a year ago, although I don't remember them at this point, I think it definitely helps solve them again. 

# Time Taken

| Set | Question | Time Taken | Attempted before |
| --- | -------- | ---------- | ---------------- |
| 1   | 1        | 0h12m      | Yes              |
| 1   | 2        | 0h15m      | Yes              |
| 1   | 3        | 0h25m      | Yes              |
| 1   | 4        | 0h14m      | Yes              |
| 1   | 5        | 0h10m      | Yes              |
| 1   | 6        | 1h21m      | Yes              |
| 1   | 7        | 0h53m      | Yes              |
| 1   | 8        | 0h10m      | Yes              |
| 2   | 9        | 0h12m      | Yes              |

# Notes

## Set 1

### Q7

- Go doesn't internally have support for AES ECB mode
- Best way is to implement cipher.Block
- Newlines by cryptopals gets to you ;( 
- You don't need to know the encryption algorithms internals to break it ;)

### Q8

- Detecting ECB mode is quite easy, how does this help us though?
