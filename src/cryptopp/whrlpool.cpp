// whrlpool.cpp - originally modified by Kevin Springle from
// Paulo Barreto and Vincent Rijmen's public domain code, whirlpool.c.
// Updated to Whirlpool version 3.0, optimized and SSE version added by Wei Dai
// All modifications are placed in the public domain

// This is the original introductory comment:

/**
 * The Whirlpool hashing function.
 *
 * <P>
 * <b>References</b>
 *
 * <P>
 * The Whirlpool algorithm was developed by
 * <a href="mailto:pbarreto@scopus.com.br">Paulo S. L. M. Barreto</a> and
 * <a href="mailto:vincent.rijmen@cryptomathic.com">Vincent Rijmen</a>.
 *
 * See
 *      P.S.L.M. Barreto, V. Rijmen,
 *      ``The Whirlpool hashing function,''
 *      NESSIE submission, 2000 (tweaked version, 2001),
 *      <https://www.cosic.esat.kuleuven.ac.be/nessie/workshop/submissions/whirlpool.zip>
 * 
 * @author  Paulo S.L.M. Barreto
 * @author  Vincent Rijmen.
 *
 * @version 3.0 (2003.03.12)
 *
 * =============================================================================
 *
 * Differences from version 2.1:
 *
 * - Suboptimal diffusion matrix replaced by cir(1, 1, 4, 1, 8, 5, 2, 9).
 *
 * =============================================================================
 *
 * Differences from version 2.0:
 *
 * - Generation of ISO/IEC 10118-3 test vectors.
 * - Bug fix: nonzero carry was ignored when tallying the data length
 *      (this bug apparently only manifested itself when feeding data
 *      in pieces rather than in a single chunk at once).
 * - Support for MS Visual C++ 64-bit integer arithmetic.
 *
 * Differences from version 1.0:
 *
 * - Original S-box replaced by the tweaked, hardware-efficient version.
 *
 * =============================================================================
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ''AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "pch.h"
#include "whrlpool.h"
#include "misc.h"
#include "cpu.h"

NAMESPACE_BEGIN(CryptoPP)

void Whirlpool_TestInstantiations()
{
	Whirlpool x;
}

void Whirlpool::InitState(HashWordType *state)
{
	memset(state, 0, 8*sizeof(state[0]));
}

void Whirlpool::TruncatedFinal(byte *hash, size_t size)
{
	ThrowIfInvalidTruncatedSize(size);

	PadLastBlock(32);
	CorrectEndianess(m_data, m_data, 32);

	m_data[m_data.size()-4] = 0;
	m_data[m_data.size()-3] = 0;
	m_data[m_data.size()-2] = GetBitCountHi();
	m_data[m_data.size()-1] = GetBitCountLo();

	Transform(m_state, m_data);
	CorrectEndianess(m_state, m_state, DigestSize());
	memcpy(hash, m_state, size);

	Restart();		// reinit for next use
}

/*
 * The number of rounds of the internal dedicated block cipher.
 */
#define R 10

/*
 * Though Whirlpool is endianness-neutral, the encryption tables are listed
 * in BIG-ENDIAN format, which is adopted throughout this implementation
 * (but little-endian notation would be equally suitable if consistently
 * employed).
 */

#if CRYPTOPP_BOOL_SSE2_ASM_AVAILABLE
CRYPTOPP_ALIGN_DATA(16) static const word64 Whirlpool_C[4*256+R] CRYPTOPP_SECTION_ALIGN16 = {
#else
static const word64 Whirlpool_C[4*256+R] = {
#endif
    W64LIT(0x18186018c07830d8), W64LIT(0x23238c2305af4626), W64LIT(0xc6c63fc67ef991b8), W64LIT(0xe8e887e8136fcdfb),
    W64LIT(0x878726874ca113cb), W64LIT(0xb8b8dab8a9626d11), W64LIT(0x0101040108050209), W64LIT(0x4f4f214f426e9e0d),
    W64LIT(0x3636d836adee6c9b), W64LIT(0xa6a6a2a6590451ff), W64LIT(0xd2d26fd2debdb90c), W64LIT(0xf5f5f3f5fb06f70e),
    W64LIT(0x7979f979ef80f296), W64LIT(0x6f6fa16f5fcede30), W64LIT(0x91917e91fcef3f6d), W64LIT(0x52525552aa07a4f8),
    W64LIT(0x60609d6027fdc047), W64LIT(0xbcbccabc89766535), W64LIT(0x9b9b569baccd2b37), W64LIT(0x8e8e028e048c018a),
    W64LIT(0xa3a3b6a371155bd2), W64LIT(0x0c0c300c603c186c), W64LIT(0x7b7bf17bff8af684), W64LIT(0x3535d435b5e16a80),
    W64LIT(0x1d1d741de8693af5), W64LIT(0xe0e0a7e05347ddb3), W64LIT(0xd7d77bd7f6acb321), W64LIT(0xc2c22fc25eed999c),
    W64LIT(0x2e2eb82e6d965c43), W64LIT(0x4b4b314b627a9629), W64LIT(0xfefedffea321e15d), W64LIT(0x575741578216aed5),
    W64LIT(0x15155415a8412abd), W64LIT(0x7777c1779fb6eee8), W64LIT(0x3737dc37a5eb6e92), W64LIT(0xe5e5b3e57b56d79e),
    W64LIT(0x9f9f469f8cd92313), W64LIT(0xf0f0e7f0d317fd23), W64LIT(0x4a4a354a6a7f9420), W64LIT(0xdada4fda9e95a944),
    W64LIT(0x58587d58fa25b0a2), W64LIT(0xc9c903c906ca8fcf), W64LIT(0x2929a429558d527c), W64LIT(0x0a0a280a5022145a),
    W64LIT(0xb1b1feb1e14f7f50), W64LIT(0xa0a0baa0691a5dc9), W64LIT(0x6b6bb16b7fdad614), W64LIT(0x85852e855cab17d9),
    W64LIT(0xbdbdcebd8173673c), W64LIT(0x5d5d695dd234ba8f), W64LIT(0x1010401080502090), W64LIT(0xf4f4f7f4f303f507),
    W64LIT(0xcbcb0bcb16c08bdd), W64LIT(0x3e3ef83eedc67cd3), W64LIT(0x0505140528110a2d), W64LIT(0x676781671fe6ce78),
    W64LIT(0xe4e4b7e47353d597), W64LIT(0x27279c2725bb4e02), W64LIT(0x4141194132588273), W64LIT(0x8b8b168b2c9d0ba7),
    W64LIT(0xa7a7a6a7510153f6), W64LIT(0x7d7de97dcf94fab2), W64LIT(0x95956e95dcfb3749), W64LIT(0xd8d847d88e9fad56),
    W64LIT(0xfbfbcbfb8b30eb70), W64LIT(0xeeee9fee2371c1cd), W64LIT(0x7c7ced7cc791f8bb), W64LIT(0x6666856617e3cc71),
    W64LIT(0xdddd53dda68ea77b), W64LIT(0x17175c17b84b2eaf), W64LIT(0x4747014702468e45), W64LIT(0x9e9e429e84dc211a),
    W64LIT(0xcaca0fca1ec589d4), W64LIT(0x2d2db42d75995a58), W64LIT(0xbfbfc6bf9179632e), W64LIT(0x07071c07381b0e3f),
    W64LIT(0xadad8ead012347ac), W64LIT(0x5a5a755aea2fb4b0), W64LIT(0x838336836cb51bef), W64LIT(0x3333cc3385ff66b6),
    W64LIT(0x636391633ff2c65c), W64LIT(0x02020802100a0412), W64LIT(0xaaaa92aa39384993), W64LIT(0x7171d971afa8e2de),
    W64LIT(0xc8c807c80ecf8dc6), W64LIT(0x19196419c87d32d1), W64LIT(0x494939497270923b), W64LIT(0xd9d943d9869aaf5f),
    W64LIT(0xf2f2eff2c31df931), W64LIT(0xe3e3abe34b48dba8), W64LIT(0x5b5b715be22ab6b9), W64LIT(0x88881a8834920dbc),
    W64LIT(0x9a9a529aa4c8293e), W64LIT(0x262698262dbe4c0b), W64LIT(0x3232c8328dfa64bf), W64LIT(0xb0b0fab0e94a7d59),
    W64LIT(0xe9e983e91b6acff2), W64LIT(0x0f0f3c0f78331e77), W64LIT(0xd5d573d5e6a6b733), W64LIT(0x80803a8074ba1df4),
    W64LIT(0xbebec2be997c6127), W64LIT(0xcdcd13cd26de87eb), W64LIT(0x3434d034bde46889), W64LIT(0x48483d487a759032),
    W64LIT(0xffffdbffab24e354), W64LIT(0x7a7af57af78ff48d), W64LIT(0x90907a90f4ea3d64), W64LIT(0x5f5f615fc23ebe9d),
    W64LIT(0x202080201da0403d), W64LIT(0x6868bd6867d5d00f), W64LIT(0x1a1a681ad07234ca), W64LIT(0xaeae82ae192c41b7),
    W64LIT(0xb4b4eab4c95e757d), W64LIT(0x54544d549a19a8ce), W64LIT(0x93937693ece53b7f), W64LIT(0x222288220daa442f),
    W64LIT(0x64648d6407e9c863), W64LIT(0xf1f1e3f1db12ff2a), W64LIT(0x7373d173bfa2e6cc), W64LIT(0x12124812905a2482),
    W64LIT(0x40401d403a5d807a), W64LIT(0x0808200840281048), W64LIT(0xc3c32bc356e89b95), W64LIT(0xecec97ec337bc5df),
    W64LIT(0xdbdb4bdb9690ab4d),