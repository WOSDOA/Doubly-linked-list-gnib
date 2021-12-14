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
    W64LIT(0xdbdb4bdb9690ab4d), W64LIT(0xa1a1bea1611f5fc0), W64LIT(0x8d8d0e8d1c830791), W64LIT(0x3d3df43df5c97ac8),
    W64LIT(0x97976697ccf1335b), W64LIT(0x0000000000000000), W64LIT(0xcfcf1bcf36d483f9), W64LIT(0x2b2bac2b4587566e),
    W64LIT(0x7676c57697b3ece1), W64LIT(0x8282328264b019e6), W64LIT(0xd6d67fd6fea9b128), W64LIT(0x1b1b6c1bd87736c3),
    W64LIT(0xb5b5eeb5c15b7774), W64LIT(0xafaf86af112943be), W64LIT(0x6a6ab56a77dfd41d), W64LIT(0x50505d50ba0da0ea),
    W64LIT(0x45450945124c8a57), W64LIT(0xf3f3ebf3cb18fb38), W64LIT(0x3030c0309df060ad), W64LIT(0xefef9bef2b74c3c4),
    W64LIT(0x3f3ffc3fe5c37eda), W64LIT(0x55554955921caac7), W64LIT(0xa2a2b2a2791059db), W64LIT(0xeaea8fea0365c9e9),
    W64LIT(0x656589650fecca6a), W64LIT(0xbabad2bab9686903), W64LIT(0x2f2fbc2f65935e4a), W64LIT(0xc0c027c04ee79d8e),
    W64LIT(0xdede5fdebe81a160), W64LIT(0x1c1c701ce06c38fc), W64LIT(0xfdfdd3fdbb2ee746), W64LIT(0x4d4d294d52649a1f),
    W64LIT(0x92927292e4e03976), W64LIT(0x7575c9758fbceafa), W64LIT(0x06061806301e0c36), W64LIT(0x8a8a128a249809ae),
    W64LIT(0xb2b2f2b2f940794b), W64LIT(0xe6e6bfe66359d185), W64LIT(0x0e0e380e70361c7e), W64LIT(0x1f1f7c1ff8633ee7),
    W64LIT(0x6262956237f7c455), W64LIT(0xd4d477d4eea3b53a), W64LIT(0xa8a89aa829324d81), W64LIT(0x96966296c4f43152),
    W64LIT(0xf9f9c3f99b3aef62), W64LIT(0xc5c533c566f697a3), W64LIT(0x2525942535b14a10), W64LIT(0x59597959f220b2ab),
    W64LIT(0x84842a8454ae15d0), W64LIT(0x7272d572b7a7e4c5), W64LIT(0x3939e439d5dd72ec), W64LIT(0x4c4c2d4c5a619816),
    W64LIT(0x5e5e655eca3bbc94), W64LIT(0x7878fd78e785f09f), W64LIT(0x3838e038ddd870e5), W64LIT(0x8c8c0a8c14860598),
    W64LIT(0xd1d163d1c6b2bf17), W64LIT(0xa5a5aea5410b57e4), W64LIT(0xe2e2afe2434dd9a1), W64LIT(0x616199612ff8c24e),
    W64LIT(0xb3b3f6b3f1457b42), W64LIT(0x2121842115a54234), W64LIT(0x9c9c4a9c94d62508), W64LIT(0x1e1e781ef0663cee),
    W64LIT(0x4343114322528661), W64LIT(0xc7c73bc776fc93b1), W64LIT(0xfcfcd7fcb32be54f), W64LIT(0x0404100420140824),
    W64LIT(0x51515951b208a2e3), W64LIT(0x99995e99bcc72f25), W64LIT(0x6d6da96d4fc4da22), W64LIT(0x0d0d340d68391a65),
    W64LIT(0xfafacffa8335e979), W64LIT(0xdfdf5bdfb684a369), W64LIT(0x7e7ee57ed79bfca9), W64LIT(0x242490243db44819),
    W64LIT(0x3b3bec3bc5d776fe), W64LIT(0xabab96ab313d4b9a), W64LIT(0xcece1fce3ed181f0), W64LIT(0x1111441188552299),
    W64LIT(0x8f8f068f0c890383), W64LIT(0x4e4e254e4a6b9c04), W64LIT(0xb7b7e6b7d1517366), W64LIT(0xebeb8beb0b60cbe0),
    W64LIT(0x3c3cf03cfdcc78c1), W64LIT(0x81813e817cbf1ffd), W64LIT(0x94946a94d4fe3540), W64LIT(0xf7f7fbf7eb0cf31c),
    W64LIT(0xb9b9deb9a1676f18), W64LIT(0x13134c13985f268b), W64LIT(0x2c2cb02c7d9c5851), W64LIT(0xd3d36bd3d6b8bb05),
    W64LIT(0xe7e7bbe76b5cd38c), W64LIT(0x6e6ea56e57cbdc39), W64LIT(0xc4c437c46ef395aa), W64LIT(0x03030c03180f061b),
    W64LIT(0x565645568a13acdc), W64LIT(0x44440d441a49885e), W64LIT(0x7f7fe17fdf9efea0), W64LIT(0xa9a99ea921374f88),
    W64LIT(0x2a2aa82a4d825467), W64LIT(0xbbbbd6bbb16d6b0a), W64LIT(0xc1c123c146e29f87), W64LIT(0x53535153a202a6f1),
    W64LIT(0xdcdc57dcae8ba572), W64LIT(0x0b0b2c0b58271653), W64LIT(0x9d9d4e9d9cd32701), W64LIT(0x6c6cad6c47c1d82b),
    W64LIT(0x3131c43195f562a4), W64LIT(0x7474cd7487b9e8f3), W64LIT(0xf6f6fff6e309f115), W64LIT(0x464605460a438c4c),
    W64LIT(0xacac8aac092645a5), W64LIT(0x89891e893c970fb5), W64LIT(0x14145014a04428b4), W64LIT(0xe1e1a3e15b42dfba),
    W64LIT(0x16165816b04e2ca6), W64LIT(0x3a3ae83acdd274f7), W64LIT(0x6969b9696fd0d206), W64LIT(0x09092409482d1241),
    W64LIT(0x7070dd70a7ade0d7), W64LIT(0xb6b6e2b6d954716f), W64LIT(0xd0d067d0ceb7bd1e), W64LIT(0xeded93ed3b7ec7d6),
    W64LIT(0xcccc17cc2edb85e2), W64LIT(0x424215422a578468), W64LIT(0x98985a98b4c22d2c), W64LIT(0xa4a4aaa4490e55ed),
	W64LIT(0x2828a0285d885075), W64LIT(0x5c5c6d5cda31b886), W64LIT(0xf8f8c7f8933fed6b), W64LIT(0x8686228644a411c2),

	W64LIT(0xd818186018c07830), W64LIT(0x2623238c2305af46), W64LIT(0xb8c6c63fc67ef991), W64LIT(0xfbe8e887e8136fcd),
    W64LIT(0xcb878726874ca113), W64LIT(0x11b8b8dab8a9626d), W64LIT(0x0901010401080502), W64LIT(0x0d4f4f214f426e9e),
    W64LIT(0x9b3636d836adee6c), W64LIT(0xffa6a6a2a6590451), W64LIT(0x0cd2d26fd2debdb9), W64LIT(0x0ef5f5f3f5fb06f7),
    W64LIT(0x967979f979ef80f2), W64LIT(0x306f6fa16f5fcede), W64LIT(0x6d91917e91fcef3f), W64LIT(0xf852525552aa07a4),
    W64LIT(0x4760609d6027fdc0), W64LIT(0x35bcbccabc897665), W64LIT(0x379b9b569baccd2b), W64LIT(0x8a8e8e028e048c01),
    W64LIT(0xd2a3a3b6a371155b), W64LIT(0x6c0c0c300c603c18), W64LIT(0x847b7bf17bff8af6), W64LIT(0x803535d435b5e16a),
    W64LIT(0xf51d1d741de8693a), W64LIT(0xb3e0e0a7e05347dd), W64LIT(0x21d7d77bd7f6acb3), W64LIT(0x9cc2c22fc25eed99),
    W64LIT(0x432e2eb82e6d965c), W64LIT(0x294b4b314b627a96), W64LIT(0x5dfefedffea321e1), W64LIT(0xd5575741578216ae),
    W64LIT(0xbd15155415a8412a), W64LIT(0xe87777c1779fb6ee), W64LIT(0x923737dc37a5eb6e), W64LIT(0x9ee5e5b3e57b56d7),
    W64LIT(0x139f9f469f8cd923), W64LIT(0x23f0f0e7f0d317fd), W64LIT(0x204a4a354a6a7f94), W64LIT(0x44dada4fda9e95a9),
    W64LIT(0xa258587d58fa25b0), W64LIT(0xcfc9c903c906ca8f), W64LIT(0x7c2929a429558d52), W64LIT(0x5a0a0a280a502214),
    W64LIT(0x50b1b1feb1e14f7f), W64LIT(0xc9a0a0baa0691a5d), W64LIT(0x146b6bb16b7fdad6), W64LIT(0xd985852e855cab17),
    W64LIT(0x3cbdbdcebd817367), W64LIT(0x8f5d5d695dd234ba), W64LIT(0x9010104010805020), W64LIT(0x07f4f4f7f4f303f5),
    W64LIT(0xddcbcb0bcb16c08b), W64LIT(0xd33e3ef83eedc67c), W64LIT(0x2d0505140528110a), W64LIT(0x78676781671fe6ce),
    W64LIT(0x97e4e4b7e47353d5), W64LIT(0x0227279c2725bb4e), W64LIT(0x7341411941325882), W64LIT(0xa78b8b168b2c9d0b),
    W64LIT(0xf6a7a7a6a7510153), W64LIT(0xb27d7de97dcf94fa), W64LIT(0x4995956e95dcfb37), W64LIT(0x56d8d847d88e9fad),
    W64LIT(0x70fbfbcbfb8b30eb), W64LIT(0xcdeeee9fee2371c1), W64LIT(0xbb7c7ced7cc791f8), W64LIT(0x716666856617e3cc),
    W64LIT(0x7bdddd53dda68ea7), W64LIT(0xaf17175c17b84b2e), W64LIT(0x454747014702468e), W64LIT(0x1a9e9e429e84dc21),
    W64LIT(0xd4caca0fca1ec589), W64LIT(0x582d2db42d75995a), W64LIT(0x2ebfbfc6bf917963), W64LIT(0x3f07071c07381b0e),
    W64LI