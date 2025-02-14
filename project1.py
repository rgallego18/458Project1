#Ryan Gallego
#CS 458 Programming Assignment 1
import struct
import sys
#this is for the binascii.unhexlify function in main
import binascii

#Does a left rotation on an (32 bit) integer
def shiftLeft(value, shift):
    #shifts the bits left, the OxFFFFFFFF ensures that it's only 32 bits once that happens
    #after the | the value >> thing moves the bits that got lost to the right
    return ((value << shift) & 0xFFFFFFFF) | (value >> (32 - shift))

#this is the salsa20 implementation, modifies the 4 values using bitwise
def quarterround(y, a, b, c, d):
    #uses the shiftLeft function to do a ton of rotations and XORs
    y[b] ^= shiftLeft((y[a] + y[d]) & 0xFFFFFFFF, 7)
    y[c] ^= shiftLeft((y[b] + y[a]) & 0xFFFFFFFF, 9)
    y[d] ^= shiftLeft((y[c] + y[b]) & 0xFFFFFFFF, 13)
    y[a] ^= shiftLeft((y[d] + y[c]) & 0xFFFFFFFF, 18)

#in salsa20, "the internal state is made of sixteen 32-bit words arranged as a 4×4 matrix"
#applies quarterround to the rows in matrix
def rowround(y):
    quarterround(y, 0, 1, 2, 3)
    quarterround(y, 5, 6, 7, 4)
    quarterround(y, 10, 11, 8, 9)
    quarterround(y, 15, 12, 13, 14)

#applies quarterround to the columns of the matrix
def columnround(y):
    quarterround(y, 0, 4, 8, 12)
    quarterround(y, 5, 9, 13, 1)
    quarterround(y, 10, 14, 2, 6)
    quarterround(y, 15, 3, 7, 11)

#applies what's called a doubleround (one columnround and then a rowround)
#Salsa20/8 uses 4 doublerounds, which is 8 total rounds
def doubleround(y):
    columnround(y)
    rowround(y)

#this takes a 64 byte "block" and does 8 rounds on it
def salsaHash(input_block):
    #unpack the integer "block" into little 32 bit integers (16 of them)
    x = list(struct.unpack("16I", input_block))
    #adds the original input to the transformed input (z)
    z = x[:]
    for _ in range(4):  #"4" for 4 double rounds
        doubleround(z)
    #put it back into 64 byte stream
    return struct.pack("16I", *[(z[i] + x[i]) & 0xFFFFFFFF for i in range(16)])

#expands the key basd on size and puts it into salsa format
def expand_key(key, nonce, block_num, key_size):
    #all constants for each key size
    constants = {64: b"expand 08-byte k", 128: b"expand 16-byte k", 256: b"expand 32-byte k"}
    
    #repeat 8 byte key 4 times
    if key_size == 64:
        key = key * 4  
    
    #repeat 8 byte key 4 times
    elif key_size == 128:
        key = key * 2  
    
    #keep it same
    elif key_size == 256:
        key = key  
    
    else:
        raise ValueError("Invalid key size. Must be 64, 128, or 256 bits.")
    
    #this makes put the initial state which is made up of constants, key, nonce, and block number
    return (constants[key_size][:4] + key[:16] +
            constants[key_size][4:8] + nonce + block_num.to_bytes(8, "little") +
            constants[key_size][8:12] + key[16:] +
            constants[key_size][12:])

#encrypts plaintext using salsa stream cipher
def salsa20_encrypt(key, nonce, plaintext, key_size):
    ciphertext = bytearray()
    #split plaintext into 64 byte "blocks"
    for i in range(0, len(plaintext), 64):
        #generate the keystream
        block_key = expand_key(key, nonce, i // 64, key_size)
        keystream = salsaHash(block_key)
        #XOR the plaintext block with keystream
        block = plaintext[i:i+64]
        #return the ciphertext hexadecimal
        ciphertext.extend([block[j] ^ keystream[j] for j in range(len(block))])
    return binascii.hexlify(ciphertext).decode()

#main function
def main():
    #this just checks the argument count, should be 4 and only 4 arguments
    if len(sys.argv) != 5:
        print("Usage: ./your_prog <key_size> <key_hex> <nonce_hex> <input_hex>")
        sys.exit(1)
    
    key_size = int(sys.argv[1])
    #the "binascii.unhexlify" converts hex inputs into binary (from python docs)
    key = binascii.unhexlify(sys.argv[2])
    nonce = binascii.unhexlify(sys.argv[3])
    input_text = binascii.unhexlify(sys.argv[4])
    #call the salsa encrypt function
    output = salsa20_encrypt(key, nonce, input_text, key_size)
    #print out the newly encrypted output
    print(f'"{output}"')

#run main
if __name__ == "__main__":
    main()