# cryptopals

Solving the matasano challenge, while timing myself doing it!

Do note that some of these were solved by me around a year ago, although I don't remember them at this point, I think it definitely helps solve them again.

# Time Taken

| Set | Question | Time Taken | Attempted before |
| --- | -------- | ---------- | ---------------- |
|   1 |        1 | 0h12m      | Yes              |
|   1 |        2 | 0h15m      | Yes              |
|   1 |        3 | 0h25m      | Yes              |
|   1 |        4 | 0h14m      | Yes              |
|   1 |        5 | 0h10m      | Yes              |
|   1 |        6 | 1h21m      | Yes              |
|   1 |        7 | 0h53m      | Yes              |
|   1 |        8 | 0h10m      | Yes              |
|   2 |        9 | 0h12m      | Yes              |
|   2 |       10 | 0h29m      | Yes              |
|   2 |       11 | 0h32m      | Yes              |
|   2 |       12 | 1h29m      | Yes              |
|   2 |       13 | 0h59m      | Yes              |
|   2 |       14 | 1h07m      | Yes              |
|   2 |       15 | 0h27m      | Yes              |
|   2 |       16 | 0h47m      | Yes              |
|   3 |       17 | 3h47m      | Yes              |
|   3 |       18 | 0h41m      | Yes              |
|   3 |       19 | 0h37m      | Yes              |
|   3 |       20 | 0h18m      | Yes              |
|   3 |       21 | 0h50m      | Yes              |
|   3 |       22 | 0h25m      | Yes              |

# Notes

## Set 1

### Q7

- Go doesn't internally have support for AES ECB mode
- Best way is to implement cipher.Block
- Newlines by cryptopals gets to you ;(
- You don't need to know the encryption algorithms internals to break it ;)

### Q8

- Detecting ECB mode is quite easy, how does this help us though?

## Set 2

### Q10

- This talks about the ECB mode code that we wrote in Q7, but in Go there is no support for ECB mode inbuilt in the crypto library.
- This means that you probably used the `cypto/aes` and built ECB over it.
- With that context the question is quite confusing as you can't really re-use the ECB code you wrote earlier. I took some time understanding the question.

### Q11

- `Rand.Intn(n int)` panics when n == 0.

### Q12

- The toughest part was coming up with a clean to calculate the required sizes of prefix

### Q14

- The question was a little confusing, it took some time to understand that the random string was fixed

## Set 3

### Q17

Theres's was a lot of initial confusion understand the question. The question fails to mention that the user has access to the IV. Which is slighyly hinted but not explicit.
Beyond this, the math while is simple, is easy to mess up. I had a lot of confusion writing the code to ensure that it worked over multiple blocks. Finally resorting to splitting the blocks and discarding solved blocks.

### Q18

LittleEndian is a little tricky because, but go has encoding/binary to help :D 

### Q19

This is similar to most of the character frequency problems we've solved earlier, matter of fact I used the character frequency solution to solve this ;) 

### Q20

This builds on top of repeating XOR decryption, using the code we built earlier, we can see how easy it is to break CTR encryption.

### Q21

We just need to follow the pseudo code on wikipedia, I got stuck with a typo in the pseudo code, which took a while for me to figure out
Verified via https://asecuritysite.com/encryption/twister

