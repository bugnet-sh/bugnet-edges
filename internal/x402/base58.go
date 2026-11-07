package x402

// alphabet58 is the Bitcoin alphabet Solana writes keys and signatures in
const alphabet58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// maxText58 is the longest text of 64 bytes, so a seller's long text costs no quadratic work
const maxText58 = 88

// digit58 is each byte's value in alphabet58, -1 for a byte outside it
var digit58 = func() [256]int8 {
	var d [256]int8
	for i := range d {
		d[i] = -1
	}
	for i := 0; i < len(alphabet58); i++ {
		d[alphabet58[i]] = int8(i)
	}
	return d
}()

// Decode58 decodes canonical base58 of up to 88 characters, false on any other text
func Decode58(s string) ([]byte, bool) {
	if s == "" || len(s) > maxText58 {
		return nil, false
	}
	zeros := 0
	for zeros < len(s) && s[zeros] == '1' {
		zeros++
	}
	// little holds the number after the leading ones, least significant byte first
	little := make([]byte, 0, len(s))
	for i := zeros; i < len(s); i++ {
		d := digit58[s[i]]
		if d < 0 {
			return nil, false
		}
		carry := int(d)
		for j := range little {
			carry += int(little[j]) * 58
			little[j] = byte(carry)
			carry >>= 8
		}
		for ; carry > 0; carry >>= 8 {
			little = append(little, byte(carry))
		}
	}
	out := make([]byte, zeros+len(little))
	for i, b := range little {
		out[len(out)-1-i] = b
	}
	return out, true
}

// Encode58 writes bytes as base58, for the fake seller and tests
func Encode58(b []byte) string {
	zeros := 0
	for zeros < len(b) && b[zeros] == 0 {
		zeros++
	}
	// little holds the base 58 digits, least significant first
	little := make([]byte, 0, len(b)*138/100+1)
	for _, v := range b[zeros:] {
		carry := int(v)
		for j := range little {
			carry += int(little[j]) << 8
			little[j] = byte(carry % 58)
			carry /= 58
		}
		for ; carry > 0; carry /= 58 {
			little = append(little, byte(carry%58))
		}
	}
	out := make([]byte, zeros+len(little))
	for i := 0; i < zeros; i++ {
		out[i] = '1'
	}
	for i, d := range little {
		out[len(out)-1-i] = alphabet58[d]
	}
	return string(out)
}
