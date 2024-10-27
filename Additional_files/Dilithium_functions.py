from Dilithium_parameters import *
import copy as py_copy
from binascii import unhexlify, hexlify

try:
    from Crypto.Hash import SHAKE256
    from Crypto.Hash import SHAKE128
except ModuleNotFoundError:
    print("Module Crypto not found, trying with Cryptodome")
    try:
        from Cryptodome.Hash import SHAKE256
        from Cryptodome.Hash import SHAKE128            
    except ModuleNotFoundError:
        print("Module Crypto AND Cryptodom not found, please verify the installation")

Q_HALF = Q >> 1
MONT_INV = 8265825

def montgomery_reduce(a):
    """
    *************************************************
    * Description: For finite field element a with 0 <= a <= Q*2^32,
    *              compute r \equiv a*2^{-32} (mod Q) such that 0 <= r < 2*Q.
    *
    * Arguments:   - int a: finite field element
    *
    * Returns:     - int r: such as in the Description.
    **************************************************
    """
    r = (a * MONT_INV) % Q
    return r - Q if r > Q_HALF else r


def reduce32(a):
    """
    *************************************************
    * Description: For finite field element a, compute r \equiv a (mod Q)
    *              such that 0 <= r < 2*Q.
    *
    * Arguments:   - int a: finite field element
    *
    * Returns:     - int r: such as in the Description.
    **************************************************
    """
    MAX_VAL = 2**31 - 2**22 - 1
    MIN_VAL = -2**31 + 2**22
    t = (a + (1 << 22)) >> 23
    t = a - t * Q  
    t = ((t + Q) & MAX_VAL) - Q if t > MAX_VAL else t    
    return t


def poly_reduce(a):
    """
    *************************************************
    * Description: Inplace reduction of all coefficients of
    *              input polynomial to representative in [0,2*Q[.
    *
    * Arguments:   - array[N](int) a: input/output polynomial
    **************************************************
    """
    for i in range(N):
        a[i] = reduce32(a[i])


def caddq(a):
    """
    *************************************************
    * Description: Subtract Q if input coefficient is negative.
    *
    * Arguments:   - int a: finite field element
    *
    * Returns:     - int r: such as in the Description.
    **************************************************
    """
    a += (a >> 31) & Q
    return a


def poly_caddq(a):
    """
    *************************************************
    * Description: For all coefficients of input polynomial add Q if
    *              coefficient is bnegative. Inplace operation.
    *
    * Arguments:   - array[N](int) a: input/output polynomial
    **************************************************
    """
    for i in range(N):
        a[i] = caddq(a[i])


def polyveck_caddq(v):
    """
    *************************************************
    * Description: For all coefficients of polynomials in vector of length K
    *              subtract Q if coefficient is negative. Inplace operation.
    *
    * Arguments:   - array[K][N](int) v: input/output vector
    **************************************************
    """
    for i in range(K):
        poly_caddq(v[i])


def poly_add(a, b):
    """
    *************************************************
    * Description: Add polynomials. No modular reduction is performed.
    *
    * Arguments:   - array[N](int) a: first summand
    *              - array[N](int) b: second summand
    *
    * Returns:     - array[N](int) c: output summed polynomial
    **************************************************
    """
    c = [0]*N
    for i in range(N):
        c[i] = a[i] + b[i]
    return c


def poly_sub(u, v):
    """
    *************************************************
    * Description: Subtract polynomials. Assumes coefficients of second input
    *              polynomial to be less than 2*Q. No modular reduction is
    *              performed.
    *
    * Arguments:   - array[N](int) a: first input polynomial
    *              - array[N](int) b: second input polynomial to be subtraced from the first one
    *
    * Returns:     - array[N](int) w: output substracted polynomial
    **************************************************
    """
    w = [0]*N
    for i in range(N):
        w[i] = u[i] +2*Q - v[i]
    return w


def polyveck_sub(u, v):
    """
    *************************************************
    * Description: Subtract vectors of polynomials of length K.
    *              Assumes coefficients of polynomials in second input vector
    *              to be less than 2*Q. No modular reduction is performed.
    *
    * Arguments:   - array[K][N](int) u: pointer to first input vector
    *              - array[K][N](int) v: pointer to second input vector to be
    *                                   subtracted from the first one
    *
    * Returns:     - array[K][N](int) w: output substracted vector
    **************************************************
    """
    w = []
    for i in range(K):
        w.append(poly_sub(u[i], v[i]))
    return w


def poly_shiftl(a):
    """
    *************************************************
    * Description: Multiply polynomial by 2^D without modular reduction. Assumes
    *              input coefficients to be less than 2^{32-D}. Inplace operation.
    *
    * Arguments:   - array[N](int) a: input/output polynomial
    **************************************************
    """
    for i in range(N):
        a[i] <<= D


def polyveck_shiftl(v):
    """
    *************************************************
    * Description: Multiply vector of polynomials of Length K by 2^D without modular
    *              reduction. Assumes input coefficients to be less than 2^{32-D}.
    *
    * Arguments:   - array[K][N](int) v: input/output vector
    **************************************************
    """
    for i in range(K):
        poly_shiftl(v[i])


def ntt(p):
    """
    *************************************************
    * Description: Forward NTT, in-place. No modular reduction is performed after
    *              additions or subtractions. Hence output coefficients can be up
    *              to 16*Q larger than the coefficients of the input polynomial.
    *              Output vector is in bitreversed order.
    *              Elements of p must be at least 32 bits long or else everflow occurs.
    *
    * Arguments:   - array[N](int) p: input/output coefficient array
    **************************************************
    """
    len_ =  128
    k = 0
    while len_ > 0:
        start = 0
        while start < 256:
            k = k + 1
            zeta = zetas[k]
            for j in range(start, start + len_):
                t = montgomery_reduce(zeta* p[j+len_])
                p[j+len_] = p[j] - t
                p[j]      = p[j] + t
                
            start = len_ + (j + 1)
        len_ >>= 1
        

def my_poly_ntt(a):
    """
    *************************************************
    * Description: Forward NTT. Output coefficients can be up to 16*Q larger than
    *              input coefficients. Inplace operation
    *
    * Arguments:   - array[N](int) a: input/output polynomial
    **************************************************
    """
    ntt(a)


def my_polyvecl_ntt(v):
    """
    *************************************************
    * Description: Forward NTT of all polynomials in vector of length L. Output
    *              coefficients can be up to 16*Q larger than input coefficients.
    *
    * Arguments:   - array[L][N](int) v: input/output vector of polynomials
    **************************************************
    """
    for i in range(L):
        my_poly_ntt(v[i])


def my_polyveck_ntt(v):
    """
    *************************************************
    * Description: Forward NTT of all polynomials in vector of length K. Output
    *              coefficients can be up to 16*Q larger than input coefficients.
    *
    * Arguments:   - array[K][N](int) v: input/output vector of polynomials
    **************************************************
    """
    for i in range(K):
        my_poly_ntt(v[i])


def invntt_frominvmont(p):
    """
    *************************************************
    * Description: backward NTT, in-place. No modular reduction is performed after
    *              additions or subtractions. Hence output coefficients can be up
    *              to 16*Q larger than the coefficients of the input polynomial.
    *              Output vector is in bitreversed order.
    *              Elements of p must be at least 32 bits long or else everflow occurs.
    *
    * Arguments:   - array[N](int) p: input/output coefficient array
    **************************************************
    """
    k = 256
    l = 1
    f = 41978
    
    while l < 256:
        start = 0
        while start < 256:
            k -= 1
            zeta = -zetas[k]
            for j in range(start, start + l):
                t        = p[j]
                p[j]     = t + p[j + l]
                p[j + l] = t - p[j + l]
                p[j + l] = montgomery_reduce(zeta * p[j + l])
            start = j + l + 1
        l = l << 1
        
    for j in range(256):
        p[j] = montgomery_reduce(f * p[j])


def poly_pointwise_invmontgomery(a, b):
    """
    *************************************************
    * Description: Pointwise multiplication of polynomials in NTT domain
    *              representation and multiplication of resulting polynomial
    *              with 2^{-32}. Output coefficients are less than 2*Q if input
    *              coefficient are less than 22*Q.
    *
    * Arguments:   - array[N](int) a: first input polynomial
    *              - array[N](int) b: second input polynomial
    *
    * Returns:     - array[N](int) c: output polynomial such as in Description.
    **************************************************
    """
    c = [0]*N
    for i in range(0, N):
        c[i] = montgomery_reduce(a[i] * b[i])
    return c


def polyvecl_pointwise_acc_invmontgomery(lA, y):
    """
    *************************************************
    * Description: Pointwise multiply vectors of polynomials of length L, multiply
    *              resulting vector by 2^{-32} and add (accumulate) polynomials
    *              in it. Input/output vectors are in NTT domain representation.
    *              Input coefficients are assumed to be less than 22*Q. Output
    *              coeffcient are less than 2*L*Q.
    *
    * Arguments:   - array[L][N](int) la: first input vector
    *              - array[L][N](int) y: second input vector
    *
    * Returns:     - array[L][N](int) lw: output vector of polynomials such as in Description.
    **************************************************
    """
    t = [0]*N
    lw = poly_pointwise_invmontgomery(lA[0], y[0])

    for i in range(1, L):
        t = poly_pointwise_invmontgomery(lA[i], y[i])
        lw = poly_add(lw, t)

    return lw


def rej_uniform(buf, buflen, len_ = N):
    """
    *************************************************
    * Description: Sample uniformly random coefficients in [0, Q-1] by
    *              performing rejection sampling using array of random bytes.
    *
    * Arguments:   - array[len_](int) A: output array (declared outside)
    *              - unsigned int len_: number of coefficients to be sampled (default: N)
    *              - str[buflen] buf: array of random bytes
    *              - int buflen: length of array of random bytes
    *
    * Returns:     - int ctr: number of sampled coefficients. Can be smaller than len_ if not enough
    *                random bytes were given.
    **************************************************
    """
    A_ = []
    ctr, pos = 0, 0
    while(ctr < len_ and pos + 3 <= buflen):
        t  = buf[pos]
        pos+= 1
        t |= (buf[pos] << 8)
        pos+=1
        t |= (buf[pos] << 16)
        pos+= 1
        t &= 0x7FFFFF

        if(t < Q):
            A_.append(t)
            ctr+=1
    return ctr, A_


def poly_uniform(seed, nonce):
    """
    *************************************************
    * Description: Sample polynomial with uniformly random coefficients
    *              in [-ETA,ETA] by performing rejection sampling using the
    *              output stream from SHAKE256(seed|nonce).
    *
    * Arguments:   - bytes[SEEDBYTES] seed: byte array with seed
    *              - int nonce: 2-byte nonce
    *
    * Returns:     - array[N](int) S: output polynomial
    **************************************************
    """
    ctr = 0
    # /!\ maybe change with ((768 + STREAM128_BLOCKBYTES - 1)//STREAM128_BLOCKBYTES)
    # nblocks = (769 + STREAM128_BLOCKBYTES)//STREAM128_BLOCKBYTES
    nblocks = ((768 + STREAM128_BLOCKBYTES - 1)//STREAM128_BLOCKBYTES)

    buflen = nblocks*STREAM128_BLOCKBYTES
    
    m = bytearray(34)
    for i in range(32):
        m[i] = seed[i]
        
    m[33] = nonce >> 8
    m[32] = nonce ^ (m[33]<<8 )

    # initialise shake
    shake = SHAKE128.new(m)

    S = []
    out = b""
    
    # First Squeeze Block
    while (nblocks > 0):
        out+= shake.read(SHAKE128_RATE)
        nblocks -= 1

    ctr, S = rej_uniform(out, buflen)

    # if not enough random bytes to fill the polynomial coefficients
    out = bytearray(out)
    
    while(ctr < N):
        off = buflen % 3
        for i in range(off):
            out[i] = out[buflen - off + i]

        buflen = STREAM128_BLOCKBYTES + off
        nblocks = 1

        while (nblocks > 0):
            out[off:] = shake.read(SHAKE128_RATE)
            nblocks -= 1

        ctr_, a = rej_uniform(out, buflen, len_ = N - ctr)
        ctr += ctr_
        S += a
    return S


def polyvec_matrix_expand(rho):
    """
    **************************************************
    * Description: Implementation of ExpandA. Generates matrix A with uniformly
    *              random coefficients a_{i,j} by performing rejection
    *              sampling on the output stream of SHAKE128(rho|i|j).
    *              warning: C version uses poly_uniform function not implemented here (maybe code it ?)
    *
    * Arguments:   - str rho: byte array containing seed rho
    *
    * Returns:     - array[K][L][N](int) A: output matrix
    **************************************************
    """
    A = []
    for i in range(K):
        A_ = []
        for j in range(L):
            A_.append(poly_uniform(rho,  (i << 8) + j))
        A.append(A_)
    return A


def polyeta_unpack(a):
    """
    *************************************************
    * Description: Unpack polynomial with coefficients in [-ETA,ETA].
    *              Output coefficients lie in [Q-ETA,Q+ETA].
    *
    * Arguments:   - bytes[POLETA_SIZE_PACKED] a: byte array with bit-packed polynomial
    *
    * Returns:     - array[N](int) r: output polynomial
    **************************************************
    """
    r = [0]*N
    if ETA == 2:
        for i in range(N//8):
            r[8*i+0] = a[3*i+0] & 0x07
            r[8*i+1] = (a[3*i+0] >> 3) & 0x07
            r[8*i+2] = ((a[3*i+0] >> 6) | (a[3*i+1] << 2)) & 0x07
            r[8*i+3] = (a[3*i+1] >> 1) & 0x07
            r[8*i+4] = (a[3*i+1] >> 4) & 0x07
            r[8*i+5] = ((a[3*i+1] >> 7) | (a[3*i+2] << 1)) & 0x07
            r[8*i+6] = (a[3*i+2] >> 2) & 0x07
            r[8*i+7] = (a[3*i+2] >> 5) & 0x07

            r[8*i+0] = ETA - r[8*i+0]
            r[8*i+1] = ETA - r[8*i+1]
            r[8*i+2] = ETA - r[8*i+2]
            r[8*i+3] = ETA - r[8*i+3]
            r[8*i+4] = ETA - r[8*i+4]
            r[8*i+5] = ETA - r[8*i+5]
            r[8*i+6] = ETA - r[8*i+6]
            r[8*i+7] = ETA - r[8*i+7]

    else:
        for i  in range(N//2):
            r[2*i+0] = a[i] & 0x0F
            r[2*i+1] = a[i] >> 4
            r[2*i+0] = ETA - r[2*i+0]
            r[2*i+1] = ETA - r[2*i+1]

    return r


def polyt0_unpack(a):
    """
    *************************************************
    * Description: Unpack polynomial t0 with coefficients in ]-2^{D-1}, 2^{D-1}].
    *              Output coefficients lie in ]Q-2^{D-1},Q+2^{D-1}].
    *
    * Arguments:   - bytes[POLT0_SIZE_PACKED] a: byte array with bit-packed polynomial
    *
    * Returns:     - array[N](int) r: output polynomial
    **************************************************
    """
    r = [0]*N
    for i in range(N//8):
        r[8*i+0]  = a[13*i+0]
        r[8*i+0] |= a[13*i+1] << 8
        r[8*i+0] &= 0x1FFF

        r[8*i+1]  = a[13*i+1] >> 5
        r[8*i+1] |= a[13*i+2] << 3
        r[8*i+1] |= a[13*i+3] << 11
        r[8*i+1] &= 0x1FFF

        r[8*i+2]  = a[13*i+3] >> 2
        r[8*i+2] |= a[13*i+4] << 6
        r[8*i+2] &= 0x1FFF

        r[8*i+3]  = a[13*i+4] >> 7
        r[8*i+3] |= a[13*i+5] << 1
        r[8*i+3] |= a[13*i+6] << 9
        r[8*i+3] &= 0x1FFF

        r[8*i+4]  = a[13*i+6] >> 4
        r[8*i+4] |= a[13*i+7] << 4
        r[8*i+4] |= a[13*i+8] << 12
        r[8*i+4] &= 0x1FFF

        r[8*i+5]  = a[13*i+8] >> 1
        r[8*i+5] |= a[13*i+9] << 7
        r[8*i+5] &= 0x1FFF

        r[8*i+6]  = a[13*i+9] >> 6
        r[8*i+6] |= a[13*i+10] << 2
        r[8*i+6] |= a[13*i+11] << 10
        r[8*i+6] &= 0x1FFF

        r[8*i+7]  = a[13*i+11] >> 3
        r[8*i+7] |= a[13*i+12] << 5
        r[8*i+7] &= 0x1FFF

        r[8*i+0] =  (1 << (D-1)) - r[8*i+0]
        r[8*i+1] =  (1 << (D-1)) - r[8*i+1]
        r[8*i+2] =  (1 << (D-1)) - r[8*i+2]
        r[8*i+3] =  (1 << (D-1)) - r[8*i+3]
        r[8*i+4] =  (1 << (D-1)) - r[8*i+4]
        r[8*i+5] =  (1 << (D-1)) - r[8*i+5]
        r[8*i+6] =  (1 << (D-1)) - r[8*i+6]
        r[8*i+7] =  (1 << (D-1)) - r[8*i+7]

    return r


def unpack_sk(sk):
    """
    *************************************************
    * Description: Unpack secret key sk = (rho, key, tr, s1, s2, t0).
    *
    * Arguments:   - str(hex) sk: input byte array
    *
    * Returns:     - bytes[SEEDBYTES] rho: output byte array for rho
    *              - str(hex) key: string of hex values containing key
    *              - str(hex) tr: string of hex values containing tr
    *              - array[L][N](int) s1: vector s1
    *              - array[K][N](int) s2: vector s2
    *              - array[K][N](int) t0: vector t1
    **************************************************
    """
    offset = 0
    # rho
    rho = unhexlify(sk[:SEEDBYTES])
    offset = SEEDBYTES

    # key
    key = sk[offset : offset + SEEDBYTES]
    offset += SEEDBYTES

    # tr
    tr = sk[offset : offset + TRBYTES]
    offset += TRBYTES

    # s1
    s1 = [ polyeta_unpack(unhexlify(sk[offset + index : offset + index + POLETA_SIZE_PACKED*2])) for index in range(0, (POLETA_SIZE_PACKED*2)*L, (POLETA_SIZE_PACKED*2))]
    offset += (POLETA_SIZE_PACKED*2)*L

    # s2
    s2 = [ polyeta_unpack(unhexlify(sk[offset + index : offset + index + POLETA_SIZE_PACKED*2])) for index in range(0, (POLETA_SIZE_PACKED*2)*K, (POLETA_SIZE_PACKED*2))]
    offset += (POLETA_SIZE_PACKED*2)*K

    # t0
    t0 = [ polyt0_unpack(unhexlify(sk[offset + index : offset + index + POLT0_SIZE_PACKED*2])) for index in range(0, (POLT0_SIZE_PACKED*2)*K, (POLT0_SIZE_PACKED*2))]

    return rho, key, tr, s1, s2, t0


def polyt1_unpack(a):
    """
    *************************************************
    * Description: Unpack polynomial t1 with 9-bit coefficients.
    *              Output coefficients are standard representatives.
    *
    * Arguments:   - bytes[POLT1_SIZE_PACKED] a: byte array with bit-packed polynomial
    *
    * Returns      - array[N](int) r: output polynomial
    **************************************************
    """
    r = [0]*N
    for i in range(N//4):
        r[4*i+0] = ((a[5*i+0] >> 0) | (a[5*i+1] << 8)) & 0x3FF
        r[4*i+1] = ((a[5*i+1] >> 2) | (a[5*i+2] << 6)) & 0x3FF
        r[4*i+2] = ((a[5*i+2] >> 4) | (a[5*i+3] << 4)) & 0x3FF
        r[4*i+3] = ((a[5*i+3] >> 6) | (a[5*i+4] << 2)) & 0x3FF
    return r


def unpack_pk(pk):
    """
    *************************************************
    * Description: Unpack public key pk = (rho, t1).
    *
    * Arguments:   - str(hex) pk: string of hex values containing bit-packed pk
    *
    * Returns:     - bytes[SEEDBYTES] rho: output byte array for rho
    *              - array[K][N](int) t1: output vector t1
    **************************************************
    """
    offset = 0
    # rho
    rho = unhexlify(pk[:SEEDBYTES])
    offset = SEEDBYTES

    # t1
    t1 = [ polyt1_unpack(unhexlify(pk[offset + index : offset + index + POLT1_SIZE_PACKED*2])) for index in range(0, (POLT1_SIZE_PACKED*2)*K, (POLT1_SIZE_PACKED*2))]

    return rho, t1


def polyz_unpack(a):
    """
    *************************************************
    * Description: Unpack polynomial z with coefficients
    *              in [-(GAMMA1 - 1), GAMMA1 - 1].
    *              Output coefficients are standard representatives.
    *
    * Arguments:   - bytes[POLZ_SIZE_PACKED] a: byte array with bit-packed polynomial
    *
    * Returns:     - array[N](int) r: output polynomial
    **************************************************
    """
    r = [0]*N
    if GAMMA1 == ( 1 << 17 ):
        for i in range(N//4):
            r[4*i+0]  = (a[9*i+0] | a[9*i+1] << 8 | a[9*i+2] << 16) & 0x3FFFF
            r[4*i+1]  = (a[9*i+2] >> 2 | a[9*i+3] << 6 | a[9*i+4] << 14) & 0x3FFFF
            r[4*i+2]  = (a[9*i+4] >> 4 | a[9*i+5] << 4 | a[9*i+6] << 12) & 0x3FFFF
            r[4*i+3]  = (a[9*i+6] >> 6 | a[9*i+7] << 2 | a[9*i+8] << 10) & 0x3FFFF

            r[4*i+0] = GAMMA1 - r[4*i+0]
            r[4*i+1] = GAMMA1 - r[4*i+1]
            r[4*i+2] = GAMMA1 - r[4*i+2]
            r[4*i+3] = GAMMA1 - r[4*i+3]


    elif GAMMA1 == ( 1 << 19 ):
        for i in range(N//2):
            r[2*i+0]  = a[5*i+0]
            r[2*i+0] |= a[5*i+1] << 8
            r[2*i+0] |= a[5*i+2] << 16
            r[2*i+0] &= 0xFFFFF

            r[2*i+1]  = a[5*i+2] >> 4
            r[2*i+1] |= a[5*i+3] << 4
            r[2*i+1] |= a[5*i+4] << 12
            r[2*i+0] &= 0xFFFFF

            r[2*i+0] = GAMMA1 - r[2*i+0]
            r[2*i+1] = GAMMA1 - r[2*i+1]

    return r


def unpack_sig(z, h, seed, sig):
    """
    *************************************************
    * Description: Unpack signature sig = (z, h, c).
    *
    * Arguments:   - array[0] z: declared array of output vector z
    *              - array[K][N](int) h: allocated array with zeros to output hint vector h
    *              - bytearray[0] seed: allocated array with zeros to output challenge polynomial
    *              - str[] sig: ascii str encoding hex value of signature
    *                size can be equal to 2*CRYPTO_BYTES if the message was not returned with the signature
    *                else it is 2*CRYPTO_BYTES + len(msg)
    *
    * Returns:     - 1 in case of malformed signature; otherwise 0.
    **************************************************
    """

    offset = 0

    # Decode seed to expand c
    seed += sig[:CTILDEBYTES].encode()
    offset += CTILDEBYTES

    # z
    [ z.append(polyz_unpack(unhexlify(sig[offset + index : offset + index + POLZ_SIZE_PACKED*2]))) for index in range(0, (POLZ_SIZE_PACKED*2)*L, (POLZ_SIZE_PACKED*2)) ]
    offset += (POLZ_SIZE_PACKED*2)*L

    # Decode h
    k = 0
    for i in range(K):
        h_ = [0]*N
        h_index = int(sig[offset + 2*OMEGA + 2*i: offset + 2*OMEGA + 2*(i+1) ], 16)
        if( h_index < k or h_index > OMEGA):
            return 1

        for j in range(k, h_index):
            # Coefficients are ordered for strong unforgeability
            if(j > k and int(sig[offset + 2*j: offset + 2*(j + 1)], 16) <= int(sig[offset + 2*(j-1): offset + 2*j], 16)):
                return 1
            h_[int(sig[offset + 2*j : offset + 2*(j + 1)], 16)] = 1

        h[i] = h_
        k = h_index

    # Extra indices are zero for strong unforgeability
    for j in range(k, OMEGA):
        if ( int(sig[offset + 2*j: offset + 2*(j + 1)], 16) ):
            return 1

    offset += (2*(OMEGA + K))
    return 0


def challenge(seed):
    """
    *************************************************
    * Description: Implementation of H. Samples polynomial with 60 nonzero
    *              coefficients in {-1,1} using the output stream of
    *              SHAKE256(mu|w1).
    *
    * Arguments:   - str(hex) mu: stirng containing mu encoded as a string oh hex values
    *              - array[K][N](int) w1: vector w1
    *
    * Returns:     - array[N](int) c: output challenge polynomial
    **************************************************
    """
    c = [0]*N
    shake = SHAKE256.new(seed)
    outbuf = shake.read(SHAKE256_RATE)

    signs = 0
    for i in range(8):
        signs |= outbuf[i] << 8*i
    pos = 8

    for i in range(N):
        c[i] = 0

    for i in range(N- TAU, N):

        while True:
            if(pos >= SHAKE256_RATE):
                outbuf += shake.read(SHAKE256_RATE)
                pos= 0
            b = outbuf[pos]
            pos += 1

            if b<= i:
                break

        c[i] = c[b]

        c[b] = 1 - 2*(signs & 1)
        signs >>= 1
    return c


def decompose(a):
    """
    *************************************************
    * Description: For finite field element a, compute high and low bits a0, a1 such that
    *              a mod^+ Q = a1*ALPHA + a0 with -ALPHA/2 < a0 <= ALPHA/2 except if
    *              a1 = (Q-1)/ALPHA where we set a1 = 0 and -ALPHA/2 <= a0 = a mod^+ Q - Q < 0.
    *              Assumes a to be standard representative.
    *
    * Arguments:   - int a: input element
    *
    * Returns:     - int a: output element a1
                   - int a0: output element Q + a0
    **************************************************
    """
    a = int(a)
    a1  = int((a + 127) >> 7)
    if GAMMA2 == (Q-1)//32:
        a1  = (a1*1025 + (1 << 21)) >> 22
        a1 &= 15
    elif GAMMA2 == (Q-1)//88:
        a1  = (a1*11275 + (1 << 23)) >> 24
        a1 ^= ((43 - a1) >> 31) & a1
    a0 = a - a1*ALPHA
    a0 -= (((Q-1)//2 - a0) >> 31) & Q
    return a1, a0


def poly_decompose(a):
    """
    *************************************************
    * Description: For all coefficients a of the input polynomial,
    *              compute high and low bits a0, a1 such a mod Q = a1*ALPHA + a0
    *              with -ALPHA/2 < a0 <= ALPHA/2 except a1 = (Q-1)/ALPHA where we
    *              set a1 = 0 and -ALPHA/2 <= a0 = a mod Q - Q < 0.
    *              Assumes coefficients to be standard representatives.
    *
    * Arguments:   - array[N](int) a: input polynomial
    *
    * Returns:     - array[N](int) a1: output polynomial with coefficients a1
    *              - array[N](int) a0: output polynomial with coefficients Q + a0
    **************************************************
    """
    a1, a0 = [0]*N, [0]*N
    for i in range(N):
        a1[i], a0[i] = decompose(a[i])
    return a1, a0


def polyveck_decompose(v):
    """
    *************************************************
    * Description: For all coefficients a of polynomials in vector of length K,
    *              compute high and low bits a0, a1 such a mod Q = a1*ALPHA + a0
    *              with -ALPHA/2 < a0 <= ALPHA/2 except a1 = (Q-1)/ALPHA where we
    *              set a1 = 0 and -ALPHA/2 <= a0 = a mod Q - Q < 0.
    *              Assumes coefficients to be standard representatives.
    *
    * Arguments:   - array[K][N](int)v: input vector of polynomials
    *
    * Returns:     - array[K][N](int) v1: output vector of polynomials with coefficients a1
    *              - array[K][N](int) v0: output vector of polynomials with coefficients Q + a0
    **************************************************
    """
    v1, v0 = [0]*K, [0]*K
    for i in range(K):
        v1[i], v0[i] = poly_decompose(v[i])
    return v1, v0


def compute_Az_minus_ct(sign, msg, pkin, Ain, t1in, t0in, verbose_ = False):
    """
    This function computes the quandtity Az - ct in dilithium.
    Parameters
    ----------
    sign       (str): Dilithium signature.
    msg        (str): A message signed by dilithium.  
    pkin       (str): Dilithium public key used to sign the message.
    Ain  (K-D array): Matrix A used in the signature.
    t1in (K-D array): Vector t1 from the public key.
    t0in (K-D array): Vector t0 from the secret key.
    verbose_  (bool): Option to print debug messages, default to False
    Returns 
    ----------
    r1   (K-D array): Vector r1 from dilithium.
    r0   (K-D array): Vector r0 from dilithium.
    c    (K-D array): Polynomial c from dilithium.
    """
    z = []
    h = [0]*K
    seed = bytearray()
    
    if(unpack_sig(z, h, seed, sign)):
        if verbose_:
            print("Problem with unpacking of sign")
        return -1
        
    c = challenge(unhexlify(seed.decode()))
    
    # Matrix-vector multiplication; compute Az - c2^dt1 
    t1f = py_copy.deepcopy(t1in)
    t0f = py_copy.deepcopy(t0in)
    
    # NTT form of z 
    zhat = py_copy.deepcopy(z)
    my_polyvecl_ntt(zhat)
    
    tmp1 = [0]*K
    for i in range(K):
        tmp1[i] = polyvecl_pointwise_acc_invmontgomery(Ain[i], zhat)
    
    polyveck_caddq(tmp1)

    chat = py_copy.deepcopy(c)
    ntt(chat)
    
    polyveck_shiftl(t1f)
    
    my_polyveck_ntt(t1f)
    t1hat = py_copy.deepcopy(t1f)
    
    tmp2 = [0]*K
    for i in range(K):
        tmp2[i] = poly_pointwise_invmontgomery(chat, t1hat[i])
    
    tmp1 = polyveck_sub(tmp1, tmp2)
    polyveck_caddq(tmp1)

    my_polyveck_ntt(t0f)
    t0hat = py_copy.deepcopy(t0f)
        
    tmp2 = [0]*K
    for i in range(K):
        tmp2[i] = poly_pointwise_invmontgomery(chat, t0hat[i])

    tmp1 = polyveck_sub(tmp1, tmp2)
    polyveck_caddq(tmp1)
        
    tmp1_ = []
    for i in range(K):
        invntt_frominvmont(tmp1[i])
        tmp1_.append(tmp1[i])

    polyveck_caddq(tmp1_)
    r1, r0 = polyveck_decompose(tmp1_)

    return r1, r0, c


def Antt2Aintt(A):
    """
    This function converts a dilithium matrix A in the NTT 
    domain to its representation in the normal domain. 
  
    Parameters
    ----------
    A (K-D array): Dilithium matrix A of shape K x L x N elements, in NTT domain.

    Returns
    ----------
    A (K-D array): Dilithium matrix A of shape K x L x N elements, in normal domain.
    """ 
    A_intt_ = []
    for i in range(K):
        A_k = []
        for j in range(L):
            a_test = py_copy.deepcopy(A[i][j])
            poly_reduce(a_test)
            invntt_frominvmont(a_test)
            A_k.append(a_test)
        A_intt_.append(A_k)
    return [[[montgomery_reduce(a) for a in al] for al in ak]for ak in A_intt_]