# Eliran,Darshan,311451322
# Python 3.6.9
from Crypto.Cipher import AES

SIZE_OF_BLOCK = 16


def cbc_custom_decrypt(k, n, cipher):
    """"

    :param k: the given key
    :param n: the number of blocks
    :param cipher: the encrypted text
    :return: plaintext before encryption
    The function firstly takes the IV from the cipher (the first 16 bytes), initializes the decipher which
    uses the ECB Mode, then the function runs in a loop, decrypts the current block which is 16 bytes long,
    does the xor operation with the encrypted block before, and concatenates the result to the plaintext.
    """
    decipher = AES.new(k, AES.MODE_ECB)
    # first decrypt first block with iv
    encrypted = cipher[0:SIZE_OF_BLOCK]
    plain_text = b''
    index = 1
    for index in range(index, n + 1):
        start_pos = index * SIZE_OF_BLOCK
        end_pos = (index + 1) * SIZE_OF_BLOCK
        block_text = decipher.decrypt(cipher[start_pos:end_pos])
        # now we xor each bit from the decrypted block and the encrypted block before him
        xor_result = xor_each_byte(block_text, encrypted)
        plain_text += xor_result
        # now the encrypted block is the current block
        encrypted = cipher[start_pos:end_pos]
    return plain_text


def cbc_flip_fix(k, n, cipher):
    """"

    :param k: the given key
    :param n: the number of blocks
    :param cipher: the encrypted text
    :return: The corrupted block after fix
    We go in a loop trying to find the first block who's bytes aren't the same, it's the the block which is corrupted,
    then we go to the next block, find the index of the byte which the bit flipped, and fix the corrupted block
    in the same byte, by flipping this bit, then we use the cbc_custom_decrypt to decrypt the fixec cipher (untill
    the fixed block) and return the fixed block.
    """
    decipher = AES.new(k, AES.MODE_ECB)
    # first decrypt first block with iv
    encrypted = cipher[0:SIZE_OF_BLOCK]
    fixed = b''
    fixed += encrypted
    index = 1
    for index in range(index, n + 1):
        start_pos = index * SIZE_OF_BLOCK
        end_pos = (index + 1) * SIZE_OF_BLOCK
        block_text = decipher.decrypt(cipher[start_pos:end_pos])
        # now we xor each bit from the decrypted block and the encrypted block before him
        xor_result = xor_each_byte(block_text, encrypted)
        # now we check if all the elements of current's decrypted block are the same
        check = xor_result.count(xor_result[0]) == len(xor_result)
        encrypted = cipher[start_pos:end_pos]
        if not check:
            # this is the i block which is messed up, so i+1 block is the one with the flipped bit
            start_pos = (index + 1) * SIZE_OF_BLOCK
            end_pos = (index + 2) * SIZE_OF_BLOCK
            next_block_text = decipher.decrypt(cipher[start_pos:end_pos])
            xor_result = xor_each_byte(next_block_text, encrypted)
            # find the unique byte
            unique = [x for x in xor_result if xor_result.count(x) == 1][0]
            # now we find the index of this byte
            index_unique = get_unique_index(xor_result, unique)
            # calcualte the difference of bit
            diff_bit = xor_result[index_unique] ^ xor_result[index_unique - 1]
            # xor the difference with the cipher to know what is the right bit
            right_bit = diff_bit ^ cipher[index * SIZE_OF_BLOCK + index_unique]
            # calculate the right block again by changing the bit to the right one instead the damaged one
            flipped = encrypted[0:index_unique] + bytes([right_bit]) + encrypted[index_unique + 1:]
            # concatenate the fixed block to the fixed cipher
            fixed += flipped
            break
        else:
            fixed += encrypted
    # we now we define the length to be untill the fixed i'th block, and use the first function
    new_n = int((len(fixed) - 1) / 16)
    decrypted_fix = cbc_custom_decrypt(k, new_n, fixed)
    return decrypted_fix[(index - 1) * 16: index * 16]


def get_unique_index(block, unique):
    """

    :param block: given block
    :param unique: the unique byte
    :return: the index of the unique byte in the block
    """

    for byte in range(0, SIZE_OF_BLOCK):
        if block[byte] == unique:
            return byte


def xor_each_byte(block, encrypted):
    """

    :param block: a given block
    :param encrypted: a given encrypted block
    :return: Xor operation between the two given blocks.
    """
    xor_result = []
    for byte in range(0, SIZE_OF_BLOCK):
        result = block[byte] ^ encrypted[byte]
        xor_result.append(result)
    # turn back the list to bytes
    xor_result = bytes(xor_result)
    return xor_result
