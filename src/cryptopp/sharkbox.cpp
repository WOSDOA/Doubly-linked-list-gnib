#include "pch.h"
#include "shark.h"

NAMESPACE_BEGIN(CryptoPP)

const byte SHARK::Enc::sbox[256] = {
177, 206, 195, 149,  90, 173, 231,   2,  77,  68, 251, 145,  12, 135, 161,  80, 
203, 103,  84, 221,  70, 143, 225,  78, 240, 253, 252, 235, 249, 196,  26, 110, 
 94, 245, 204, 141,  28,  86,  67, 254,   7,  97, 248, 117,  89, 255,   3,  34, 
138, 209,  19, 238, 136,   0,  14,  52,  21, 128, 148, 227, 237, 181,  83,  35, 
 75,  71,  23, 167, 144,  53, 171, 216, 184, 223,  79,  87, 154, 146, 219,  27, 
 60, 200, 153,   4, 142, 224, 215, 125, 133, 187,  64,  44,  58,  69, 241,  66, 
101,  32,  65,  24, 114,  37, 147, 112,  54,   5, 242,  11, 163, 121, 236,   8, 
 39,  49,  50, 182, 124, 176,  10, 115,  91, 123, 183, 129, 210,  13, 106,  38, 
158,  88, 156, 131, 116, 179, 172,  48, 122, 105, 119,  15, 174,  33, 222, 208, 
 46, 151,  16, 164, 152, 168, 212, 104,  45,  98,  41, 109,  22,  73, 118, 199, 
232, 193, 150,  55, 229, 202, 244, 233,  99,  18, 194, 166,  20, 188, 211,  40, 
175,  47, 230,  36,  82, 198, 160,   9, 189, 140, 207,  93,  17,  95,   1, 197, 
159,  61, 162, 155, 201,  59, 190,  81,  25,  31,  63,  92, 178, 239,  74, 205, 
191, 186, 111, 100, 217, 243,  62, 180, 170, 220, 213,   6, 192, 126, 246, 102, 
108, 132, 113,  56, 185,  29, 127, 157,  72, 139,  42, 218, 165,  51, 130,  57, 
214, 120, 134, 250, 228,  43, 169,  30, 137,  96, 107, 234,  85,  76, 247, 226, 
};

const byte SHARK::Dec::sbox[256] = {
 53, 190,   7,  46,  83, 105, 219,  40, 111, 183, 118, 107,  12, 125,  54, 139, 
146, 188, 169,  50, 172,  56, 156,  66,  99, 200,  30,  79,  36, 229, 247, 201, 
 97, 141,  47,  63, 179, 101, 127, 112, 175, 154, 234, 245,  91, 152, 144, 177, 
135, 113, 114, 237,  55,  69, 104, 163, 227, 239,  92, 197,  80, 193, 214, 202, 
 90,  98,  95,  38,   9,  93,  20,  65, 232, 157, 206,  64, 253,   8,  23,  74, 
 15, 199, 180,  62,  18, 252,  37,  75, 129,  44,   4, 120, 203, 187,  32, 189, 
249,  41, 153, 168, 211,  96, 223,  17, 151, 137, 126, 250, 224, 155,  31, 210, 
103, 226, 100, 119, 132,  43, 158, 138, 241, 109, 136, 121, 116,  87, 221, 230, 
 57, 123, 238, 131, 225,  88, 242,  13,  52, 248,  48, 233, 185,  35,  84,  21, 
 68,  11,  77, 102,  58,   3, 162, 145, 148,  82,  76, 195, 130, 231, 128, 192, 
182,  14, 194, 108, 147, 236, 171,  67, 149, 246, 216,  70, 134,   5, 140, 176, 
117,   0, 204, 133, 215,  61, 115, 122,  72, 228, 209,  89, 173, 184, 198, 208, 
220, 161, 170,   2,  29, 191, 181, 159,  81, 196, 165,  16,  34, 207,   1, 186, 
143,  49, 124, 174, 150, 218, 240,  86,  71, 212, 235,  78, 217,  19, 142,  73, 
 85,  22, 255,  59, 244, 164, 178,   6, 160, 167, 251,  27, 110,  60,  51, 205, 
 24,  94, 106, 213, 166,  33, 222, 254,  42,  28, 243,  10,  26,  25,  39,  45, 
};

const word64 SHARK::Enc::cbox[8][256] = {
/* box 0 */
W64LIT(0x060d838f16f3a365),
W64LIT(0xa68857ee5cae56f6),
W64LIT(0xebf516353c2c4d89),
W64LIT(0x652174be88e85bdc),
W64LIT(0x0d4e9a8086c17921),
W64LIT(0x27ba7d33cffa58a1),
W64LIT(0x88d9e104a237b530),
W64LIT(0x693b8755a4fbe816),
W64LIT(0xdac9591826b254a0),
W64LIT(0x45c2e369fb336af3),
W64LIT(0xa96e1fb87b3e4ef4),
W64LIT(0xb7578f1435eb7ef0),
W64LIT(0x839af80b32056f74),
W64LIT(0xae37f55cc71f277a),
W64LIT(0xa4208538fdff37d5),
W64LIT(0x35991e74ad3cdb6f),
W64LIT(0xba191594b32a07d1),
W64LIT(0x5344d1772e572b7b),
W64LIT(0xe7efe5de103ffe43),
W64LIT(0xa3796fdc41de5e5b),
W64LIT(0x2cf9643c5fc882e5),
W64LIT(0xffdbf6fd48196d22),
W64LIT(0x33949dfbbbcf780a),
W64LIT(0x7d15679dd0cec8bd),
W64LIT(0x5f5e229c024498b1),
W64LIT(0x1223634762c683ce),
W64LIT(0xdcc4da973041f7c5),
W64LIT(0x0b43190f9032da44),
W64LIT(0xc05598eddfc5a6e2),
W64LIT(0x9e5fd31a7753f4b8),
W64LIT(0x9afa8243c0f136fe),
W64LIT(0xcc4f6b06f3d61528),
W64LIT(0xdf38612a3bc25c0d),
W64LIT(0x43cf60e6edc0c996),
W64LIT(0xcfb3d0bbf855bee0),
W64LIT(0x96e071a8ece28534),
W64LIT(0x21b7febcd909fbc4),
W64LIT(0x8ed4628bb4c41655),
W64LIT(0x30682646b04cd3c2),
W64LIT(0xb5ff5dc294ba1fd3),
W64LIT(0x75aac52f4b7fb931),
W64LIT(0xe809ad8837afe641),
W64LIT(0x0eb2213d8d42d2e9),
W64LIT(0x9852509561a057dd),
W64LIT(0xaa92a40570bde53c),
W64LIT(0x7b18e412c63d6bd8),
W64LIT(0xa7dc3e85f67c9c1d),
W64LIT(0xd8618bce87e33583),
W64LIT(0xe34ab487a79d3c05),
W64LIT(0x20e397d773db312f),
W64LIT(0x05f138321d7008ad),
W64LIT(0x17d25b757fb68b63),
W64LIT(0x8a7133d20366d413),
W64LIT(0x0000000000000000),
W64LIT(0xeaa17f5e96fe8762),
W64LIT(0xc101f18675176c09),
W64LIT(0xbebc44cd0488c597),
W64LIT(0xdb9d30738c609e4b),
W64LIT(0xabc6cd6eda6f2fd7),
W64LIT(0x5aaf1aae1f34901c),
W64LIT(0xb00e65f089ca177e),
W64LIT(0xd47b7825abf08649),
W64LIT(0x924520f15b404772),
W64LIT(0x1686321ed5644188),
W64LIT(0x618425e73f4a999a),
W64LIT(0xe21eddec0d4ff6ee),
W64LIT(0xd787c398a0732d81),
W64LIT(0x1f6df9c7e407faef),
W64LIT(0x79b036c4676c0afb),
W64LIT(0x0fe6485627901802),
W64LIT(0x9cf701ccd602959b),
W64LIT(0xbfe82da6ae5a0f7c),
W64LIT(0x990639fecb729d36),
W64LIT(0xca42e889e525b64d),
W64LIT(0xb3f2de4d8249bcb6),
W64LIT(0x4033db5be643625e),
W64LIT(0x4167b2304c91a8b5),
W64LIT(0x108bb191c397e2ed),
W64LIT(0x1834132358269361),
W64LIT(0x541d3b93927642f5),
W64LIT(0x90edf227fa112651),
W64LIT(0x1dc52b1145569bcc),
W64LIT(0xe6bb8cb5baed34a8),
W64LIT(0xd276fbaabd03252c),
W64LIT(0x313c4f2d1a9e1929),
W64LIT(0xfd73242be9480c01),
W64LIT(0x9baeeb286a23fc15),
W64LIT(0xc9be5334eea61d85),
W64LIT(0xc70c720963e4cf6c),
W64LIT(0x3eda077b3d0e012b),
W64LIT(0x97b418c346304fdf),
W64LIT(0x32c0f490111db2e1),
W64LIT(0x2ba08ed8e3e9eb6b),
W64LIT(0x8b255ab9a9b41ef8),
W64LIT(0x91b99b4c50c3ecba),
W64LIT(0xfe8f9f96e2cba7c9),
W64LIT(0x3a7f56228aacc36d),
W64LIT(0xb15a0c9b2318dd95),
W64LIT(0x5953a11314b73bd4),
W64LIT(0xf3c10516640adee8),
W64LIT(0xedf895ba2adfeeec),
W64LIT(0xadcb4ee1cc9c8cb2),
W64LIT(0xde6c0841911096e6),
W64LIT(0x84c312ef8e2406fa),
W64LIT(0xa83a76d3d1ec841f),
W64LIT(0x1c91427aef845127),
W64LIT(0x3665a5c9a6bf70a7),
W64LIT(0xf6303d24797ad645),
W64LIT(0xcd1b026d5904dfc3),
W64LIT(0x1bc8a89e53a538a9),
W64LIT(0x7ee9dc20db4d6375),
W64LIT(0x51ec03a18f064a58),
W64LIT(0xc4f0c9b4686764a4),
W64LIT(0xdd90b3fc9a933d2e),
W64LIT(0x7a4c8d796cefa133),
W64LIT(0x73a746a05d8c1a54),
W64LIT(0x0759eae4bc21698e),
W64LIT(0xc8ea3a5f4474d76e),
W64LIT(0x38d784f42bfda24e),
W64LIT(0x231f2c6a78589ae7),
W64LIT(0xc3a92350d4460d2a),
W64LIT(0x72f32fcbf75ed0bf),
W64LIT(0xbd40ff700f0b6e5f),
W64LIT(0x157a89a3dee7ea40),
W64LIT(0x873fa95285a7ad32),
W64LIT(0x4d7d41db60821b7f),
W64LIT(0x1e3990ac4ed53004),
W64LIT(0x0a1770643ae010af),
W64LIT(0x9311499af1928d99),
W64LIT(0x64751dd5223a9137),
W64LIT(0xfa2acecf5569658f),
W64LIT(0x7c410ef67a1c0256),
W64LIT(0x56b5e945332723d6),
W64LIT(0x6f3604dab2084b73),
W64LIT(0xe95dc4e39d7d2caa),
W64LIT(0x13770a2cc8144925),
W64LIT(0xbc14961ba5d9a4b4),
W64LIT(0xb9e5ae29b8a9ac19),
W64LIT(0xf169d7c0c55bbfcb),
W64LIT(0x2446c68ec479f369),
W64LIT(0x806643b63986c4bc),
W64LIT(0x7fbdb54b719fa99e),
W64LIT(0x04a55159b7a2c246),
W64LIT(0xee042e07215c4524),
W64LIT(0x5bfb73c5b5e65af7),
W64LIT(0x0c1af3eb2c13b3ca),
W64LIT(0xa22d06b7eb0c94b0),
W64LIT(0xb8b1c742127b66f2),
W64LIT(0x285c3565e86a40a3),
W64LIT(0x3b2b3f49207e0986),
W64LIT(0x3c72d5ad9c5f6008),
W64LIT(0x770217f9ea2ed812),
W64LIT(0xfc274d40439ac6ea),
W64LIT(0x4fd5930dc1d37a5c),
W64LIT(0x2e51b6eafe99e3c6),
W64LIT(0x6b93558305aa8935),
W64LIT(0x19607a48f2f4598a),
W64LIT(0x08bfa2b29bb1718c),
W64LIT(0x3f8e6e1097dccbc0),
W64LIT(0x3983ed9f812f68a5),
W64LIT(0xac9f278a664e4659),
W64LIT(0x82ce916098d7a59f),
W64LIT(0xc2fd4a3b7e94c7c1),
W64LIT(0x66ddcf03836bf014),
W64LIT(0xe1e2665106cc5d26),
W64LIT(0x74feac44e1ad73da),
W64LIT(0x8d28d936bf47bd9d),
W64LIT(0x62789e5a34c93252),
W64LIT(0x81322add93540e57),
W64LIT(0xcb1681e24ff77ca6),
W64LIT(0x2512afe56eab3982),
W64LIT(0xd18a4017b6808ee4),
W64LIT(0x705bfd1d560fb19c),
W64LIT(0x4b70c2547671b81a),
W64LIT(0x49d81082d720d939),
W64LIT(0xe0b60f3aac1e97cd),
W64LIT(0x4e81fa666b01b0b7),
W64LIT(0x951cca15e7612efc),
W64LIT(0x463e58d4f0b0c13b),
W64LIT(0x632cf7319e1bf8b9),
W64LIT(0x5ca2992109c73379),
W64LIT(0xf764544fd3a81cae),
W64LIT(0x6ac73ce8af7843de),
W64LIT(0x9f0bba71dd813e53),
W64LIT(0x85977b8424f6cc11),
W64LIT(0x5807c878be65f13f),
W64LIT(0x686fee3e0e2922fd),
W64LIT(0x78e45fafcdbec010),
W64LIT(0x6ccabf67b98be0bb),
W64LIT(0x11dfd8fa69452806),
W64LIT(0xcee7b9d05287740b),
W64LIT(0x50b86aca25d480b3),
W64LIT(0x5df6f04aa315f992),
W64LIT(0x5e0a4bf7a896525a),
W64LIT(0x03fcbbbd0b83abc8),
W64LIT(0x8f800be01e16dcbe),
W64LIT(0xd32292c117d1efc7),
W64LIT(0xe5473708b16e9f60),
W64LIT(0x224b4501d28a500c),
W64LIT(0xfb7ea7a4ffbbaf64),
W64LIT(0x3d26bcc6368daae3),
W64LIT(0x866bc0392f7567d9),
W64LIT(0x3731cca20c6dba4c),
W64LIT(0xb603e67f9f39b41b),
W64LIT(0xa1d1bd0ae08f3f78),
W64LIT(0xd935e2a52d31ff68),
W64LIT(0xaf639c376dcded91),
W64LIT(0x0154696baad2caeb),
W64LIT(0xecacfcd1800d2407),
W64LIT(0xf03dbeab6f897520),
W64LIT(0x02a8d2d6a1516123),
W64LIT(0xf498eff2d82bb766),
W64LIT(0x710f9476fcdd7b77),
W64LIT(0xf8821c19f43804ac),
W64LIT(0xf9d675725eeace47),
W64LIT(0x1a9cc1f5f977f242),
W64LIT(0x5210b81c8485e190),
W64LIT(0x6d9ed60c13592a50),
W64LIT(0xf2956c7dced81403),
W64LIT(0xbb4d7cff19f8cd3a),
W64LIT(0x4c2928b0ca50d194),
W64LIT(0x6e626db118da8198),
W64LIT(0xe4135e631bbc558b),
W64LIT(0x9da368a77cd05f70),
W64LIT(0xa574ec53572dfd3e),
W64LIT(0x09ebcbd93163bb67),
W64LIT(0x4a24ab3fdca372f1),
W64LIT(0x429b098d4712037d),
W64LIT(0x57e1802e99f5e93d),
W64LIT(0xef50476c8b8e8fcf),
W64LIT(0xa085d4614a5df593),
W64LIT(0x34cd771f07ee1184),
W64LIT(0xc6581b62c9360587),
W64LIT(0x2dad0d57f51a480e),
W64LIT(0x898d886f08e57fdb),
W64LIT(0xd6d3aaf30aa1e76a),
W64LIT(0x76567e9240fc12f9),
W64LIT(0xb4ab34a93e68d538),
W64LIT(0xb2a6b726289b765d),
W64LIT(0x8c7cb05d15957776),
W64LIT(0x554952f838a4881e),
W64LIT(0xd52f114e01224ca2),
W64LIT(0x60d04c8c95985371),
W64LIT(0x6789a66829b93aff),
W64LIT(0x2f05df81544b292d),
W64LIT(0x476a31bf5a620bd0),
W64LIT(0xf5cc869972f97d8d),
W64LIT(0x488c79e97df213d2),
W64LIT(0x44968a0251e1a018),
W64LIT(0x26ee14586528924a),
W64LIT(0xd0de297c1c52440f),
W64LIT(0xc5a4a0dfc2b5ae4f),
W64LIT(0x29085c0e42b88a48),
W64LIT(0x142ee0c8743520ab),
W64LIT(0x2af4e7b3493b2180),
W64LIT(0x9448a37e4db3e417),
/* box 1 */
W64LIT(0xe2795ba105ba30ce),
W64LIT(0x65b5d634f5e0fbdd),
W64LIT(0x2d7d7f1464dd8c55),
W64LIT(0xeefbf778add1c20b),
W64LIT(0x1eb0fbd1f11968e7),
W64LIT(0xe6073f45ce30cd8d),
W64LIT(0x21ffd3cdccb67e90),
W64LIT(0xdf0941cfa750a262),
W64LIT(0xc61df5b1b75ef18a),
W64LIT(0xc5c7defa9dc337c6),
W64LIT(0x2581b729073c83d3),
W64LIT(0xa5e97513167173cf),
W64LIT(0xdd3673bd381526b9),
W64LIT(0xe8baa1eef91ebb93),
W64LIT(0x3b314cf8f625eb34),
W64LIT(0x579d4bc8d5fc5df8),
W64LIT(0xbb598ec2e7681b28),
W64LIT(0xc8a06b1a80708794),
W64LIT(0x1c8fc9a36e5cec3c),
W64LIT(0xf60a5a3f0807d374),
W64LIT(0x1ace9f353a9395a4),
W64LIT(0x7e9e50387aab2cee),
W64LIT(0xb5e41069d0466d36),
W64LIT(0x8cea6ee3b92602d9),
W64LIT(0xf952ddad8af1e7fd),
W64LIT(0xb19a748d1bcc9075),
W64LIT(0x2464ae10b2e4c144),
W64LIT(0xfcc9a070f4a35829),
W64LIT(0xfa88f6e6a06c21b1),
W64LIT(0x2c98662dd105cec2),
W64LIT(0x9065a740d77aeee5),
W64LIT(0xcb7a4051aaed41d8),
W64LIT(0x55a279ba4ab9d923),
W64LIT(0x27be855b98790708),
W64LIT(0xbabc97fb52b059bf),
W64LIT(0xa19711f7ddfb8e8c),
W64LIT(0x047e64e4cb8afd43),
W64LIT(0xc386886cc90c4e5e),
W64LIT(0xc422c7c3281b7551),
W64LIT(0xfb6defdf15b46326),
W64LIT(0x01e51939b5d84297),
W64LIT(0x5cbba8be9c809432),
W64LIT(0x6f762c7b09447080),
W64LIT(0xcee13d8cd4bffe0c),
W64LIT(0x54476083ff619bb4),
W64LIT(0x6e933542bc9c3217),
W64LIT(0x4af79b520e78f353),
W64LIT(0x98996f7db49be163),
W64LIT(0xa07208ce6823cc1b),
W64LIT(0x2b3c29823012f5cd),
W64LIT(0x93bf8c0bfde728a9),
W64LIT(0x2225f886e62bb8dc),
W64LIT(0x7f7b4901cf736e79),
W64LIT(0x0000000000000000),
W64LIT(0x023f32729f4584db),
W64LIT(0xd5cabb805bf4293f),
W64LIT(0x07a44fafe1173b0f),
W64LIT(0xe95fb8d74cc6f904),
W64LIT(0x7b052de504f9933a),
W64LIT(0x6aed51a67716cf54),
W64LIT(0x68d263d4e8534b8f),
W64LIT(0xa96bd9cabe1a810a),
W64LIT(0x1d6ad09adb84aeab),
W64LIT(0x0d67b5e01db3b052),
W64LIT(0x52063615abaee22c),
W64LIT(0x8f3045a893bbc495),
W64LIT(0xd8ad0e604647996d),
W64LIT(0xaf2a8f5cead5f892),
W64LIT(0x3017af8ebf5922fe),
W64LIT(0x4034611df2dc780e),
W64LIT(0x721cfce1d2c0de2b),
W64LIT(0x28e602c91a8f3381),
W64LIT(0xe1a370ea2f27f682),
W6