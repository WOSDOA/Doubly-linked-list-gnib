// private header for Serpent and Sosemanuk

NAMESPACE_BEGIN(CryptoPP)

// linear transformation
#define LT(i,a,b,c,d,e)	{\
	a = rotlFixed(a, 