/*
* Logic Quest (LQ): Task 3A Path Planner with Decryption
*
* Computes the shortest path on the Logic Quest arena (nodes N1..N36), with the
* line weights of Figure 1 on the Task 3A page: straight line 5, ring arcs
* 7 / 11 / 15 / 19 (inner ring to outermost ring), wavy line N1-N36 100.
*
* Inputs : current_node, next_node, is_encrypted
*   current_node     : where the bot is, 1..36. The path starts here.
*                      At the first location the bot is in the start box, N35.
*   is_encrypted = 0 : next_node is a node number.
*                      Path: current_node -> next_node.
*   is_encrypted = 1 : next_node is the 8-byte encrypted code, encrypted with
*                      PRESENT-80.
*                      Path: current_node -> the drop node in the block.
*
* Decrypted code (8 bytes, byte 0 first):
*   byte 0     : done flag (1 = last block: no pick-up after this drop)
*   byte 1..5  : message, 5 ASCII characters (0x00 = no character)
*   byte 6     : next pick-up node 1..36 (not used when the done flag is 1)
*   byte 7     : drop node 1..36 for this block
*   e.g. message "HELLO", drop at N26, then pick up at N12
*        -> 00 48 45 4C 4C 4F 0C 1A = 0048454C4C4F0C1A
*
* Outputs:
*   is_encrypted = 0 : the path from current_node to next_node.
*   is_encrypted = 1 : the message (message[]) and the path from current_node
*                      to the drop node. When the done flag is 0, the inputs
*                      for the next run are written too:
*                          IS_ENCRYPTED = 0
*                          CURRENT_NODE = the drop node
*                          NEXT_NODE    = the next pick-up node
*                      When the done flag is 1, the inputs are left as they are.
*
* Output (PC), read by test.sh line by line:
*   is_encrypted = 0     is_encrypted = 1, done = 0     is_encrypted = 1, done = 1
*   35                   Message : HELLO                Message : BYE
*   ...                  7                              7
*   7                    ...                            ...
*                        26                             26
*                        Next current_node : 26         Done
*                        Next next_node : 12
*   The path is one node per line, first node first. The message line shows
*   the non-zero message bytes as characters. The code at the end of main
*   prints all of this from message[], path_planned[], idx and the inputs
*   written for the next run.
*
* Debug prints: start every debug line with "dbg:" (see Functions Usage
*   below). test.sh and the evaluator skip the lines that start with "dbg:".
*   Any other extra line counts as part of your output and makes it wrong.
*
* PRESENT-80 (the cipher used for the encrypted codes):
*   block 64 bits, key 80 bits = A1 B2 C3 D4 E5 F6 07 18 29 3A (PRESENT_KEY_* below),
*   31 rounds. See the Task 3A page for the full description of the encryption;
*   your program has to do the reverse.
*
* Data memory ranges (used on the RISC-V CPU, Task 3B):
*   0x02000000 .. 0x0200000F : inputs
*   0x02000010 .. 0x0200001F : outputs (0x0200001C = CPU_DONE)
*   0x02000020 and up        : working memory, stack at the top
*
* Inputs  : ENCRYPTED_HI (0x02000000)  encrypted block, bytes 0..3 (first 8 hex digits)
*           ENCRYPTED_LO (0x02000004)  encrypted block, bytes 4..7 (last 8 hex digits)
*           IS_ENCRYPTED (0x02000008)  0 or 1                            } written for
*           NEXT_NODE    (0x0200000C)  next node, when IS_ENCRYPTED = 0   } the next run
*           CURRENT_NODE (0x0200000D)  current node (where the bot is)    } when done = 0
* Outputs : MESSAGE_0..4 (0x02000010 .. 0x02000014)  message, block bytes 1..5
*           NODE_POINT   (0x02000018)  every node of the path, written in order
*           CPU_DONE     (0x0200001C)  = 1 when finished
*
* Make sure you don't change anything outside the "Add your code here" sections.
*/

#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <limits.h>

// PRESENT-80 key: A1 B2 C3 D4 E5 F6 07 18 29 3A
#define PRESENT_KEY_HI  0xA1B2C3D4   // key bits 79..48
#define PRESENT_KEY_MID 0xE5F60718   // key bits 47..16
#define PRESENT_KEY_LO  0x293A       // key bits 15..0

#ifdef __linux__ // for host pc

    #include <stdio.h>

    void _put_byte(char c) { putchar(c); }

    void _put_str(char *str) {
        while (*str) {
            _put_byte(*str++);
        }
    }

    void print_output(uint8_t num) {
        if (num == 0) {
            putchar('0'); // if the number is 0, directly print '0'
            _put_byte('\n');
            return;
        }

        // convert the integer to a string
        char buffer[20];
        uint8_t index = 0;

        while (num > 0) {
            buffer[index++] = '0' + num % 10; // convert the last digit to its character representation
            num /= 10;                        // move to the next digit
        }
        // print the characters in reverse order (from right to left)
        while (index > 0) { putchar(buffer[--index]); }
        _put_byte('\n');
    }

    void _put_value(uint8_t val) { print_output(val); }

    // print a 32-bit value as 8 hex digits and a newline (e.g. the decrypted block)
    void _put_hex(uint32_t val) { printf("%08X\n", (unsigned int)val); }

    // read 16 hex digits into two 32-bit words, returns 0 if the text is not 16 hex digits
    int read_block(const char *hex, uint32_t *hi, uint32_t *lo) {
        uint32_t word[2] = { 0, 0 };
        if (hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X')) hex += 2;
        for (int n = 0; n < 16; n++) {
            char c = hex[n];
            uint32_t d;
            if      (c >= '0' && c <= '9') d = c - '0';
            else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
            else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
            else return 0;
            word[n >> 3] = (word[n >> 3] << 4) | d;
        }
        if (hex[16] != '\0') return 0;
        *hi = word[0];
        *lo = word[1];
        return 1;
    }

    /*
     * On the PC there is no data memory at 0x02000000, so MEM32(address) is a
     * normal array (one entry per 32-bit word). On the CPU it is the real
     * data memory. Either way, MEM32(0x02000020) reads the same place.
     */
    static uint32_t pc_data_mem[128];
    #define MEM32(addr)  (pc_data_mem[((addr) - 0x02000000u) >> 2])

#else  // for the test device

    void _put_byte(char c) { }
    void _put_value(uint8_t val) { }
    void _put_hex(uint32_t val) { }
    void _put_str(char *str) { }

    #define MEM32(addr)  (*(volatile uint32_t *)(addr))

#endif

/*
Functions Usage

To print while debugging, use the functions below, not printf().
On the PC they print. On the CPU they are empty, so they cost nothing there
and the same file still builds with generatehex.sh.

for a character: _put_byte('A');                        (putchar() on the PC)
for newline:     _put_byte('\n');
for string:      _put_str("your string here");
for number:      _put_value(your_number_here);           0 to 255, then a newline
for 32 bits:     _put_hex(your_32_bit_value_here);       8 hex digits, then a newline

Start every debug line with "dbg:" and end it with a newline (_put_value
and _put_hex end the line for you). test.sh and the evaluator skip the
lines that start with "dbg:", so these prints can stay in the file you
submit. Any other line you print counts as part of your output (see
"Output (PC)" at the top) and makes it wrong.

Examples:
        _put_str("dbg: start_point = ");     _put_value(start_point);
        _put_str("dbg: end_point = ");       _put_value(end_point);
        _put_str("dbg: ENCRYPTED_HI = ");    _put_hex(ENCRYPTED_HI);    // encrypted block, bytes 0..3
        _put_str("dbg: ENCRYPTED_LO = ");    _put_hex(ENCRYPTED_LO);    // encrypted block, bytes 4..7
        _put_str("dbg: first character = "); _put_byte(message[0]); _put_byte('\n');
        _put_str("dbg: Hello World!\n");

*/

// Custom Functions

// ############# Add your code here #############
#define EDGE(n, w) ((uint16_t)(((w) << 6) | (n)))

static const uint8_t sbox[16] = {
    0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD,
    0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2
};

static const uint8_t isbox[16] = {
    0x5, 0xE, 0xF, 0x8, 0xC, 0x1, 0x2, 0xD,
    0xB, 0x4, 0x6, 0x3, 0x0, 0x7, 0x9, 0xA
};

static const uint16_t graph[36][4] = {
    {EDGE(36, 100), EDGE(5, 5),  EDGE(4, 15),  EDGE(6, 15)},
    {EDGE(4, 5),    0,           0,             0},
    {EDGE(6, 5),    0,           0,             0},
    {EDGE(2, 5),    EDGE(1, 15), EDGE(14, 15), 0},
    {EDGE(1, 5),    EDGE(7, 11), EDGE(8, 11),   0},
    {EDGE(3, 5),    EDGE(1, 15), EDGE(20, 15),  0},
    {EDGE(5, 11),   EDGE(10, 5), EDGE(15, 11),  0},
    {EDGE(5, 11),   EDGE(11, 5), EDGE(20, 11),  0},
    {EDGE(11, 7),   EDGE(12, 5), 0,             0},
    {EDGE(7, 5),    0,           0,             0},
    {EDGE(8, 5),    EDGE(9, 7),  EDGE(19, 7),   0},
    {EDGE(9, 5),    0,           0,             0},
    {EDGE(14, 5),   EDGE(30, 19),0,             0},
    {EDGE(13, 5),   EDGE(15, 5), EDGE(4, 15),   0},
    {EDGE(14, 5),   EDGE(7, 11), 0,             0},
    {EDGE(17, 5),   EDGE(23, 7), 0,             0},
    {EDGE(16, 5),   0,           0,             0},
    {EDGE(19, 5),   0,           0,             0},
    {EDGE(18, 5),   EDGE(11, 7), 0,             0},
    {EDGE(21, 5),   EDGE(6, 15), EDGE(8, 11),   EDGE(27, 11)},
    {EDGE(20, 5),   0,           0,             0},
    {EDGE(25, 5),   0,           0,             0},
    {EDGE(16, 7),   EDGE(25, 7), EDGE(26, 5),   0},
    {EDGE(27, 5),   0,           0,             0},
    {EDGE(22, 5),   EDGE(23, 7), 0,             0},
    {EDGE(23, 5),   EDGE(29, 11),0,             0},
    {EDGE(24, 5),   EDGE(20, 11),EDGE(29, 11),  0},
    {EDGE(31, 5),   EDGE(32, 15),0,             0},
    {EDGE(26, 11),  EDGE(27, 11),EDGE(32, 5),   0},
    {EDGE(33, 5),   EDGE(13, 19),EDGE(35, 19),  0},
    {EDGE(28, 5),   EDGE(34, 5), EDGE(35, 19),  0},
    {EDGE(29, 5),   EDGE(28, 15),0,             0},
    {EDGE(30, 5),   0,           0,             0},
    {EDGE(31, 5),   0,           0,             0},
    {EDGE(30, 19),  EDGE(31, 19),0,             0},
    {EDGE(1, 100),  0,           0,             0}
};

static void key_next(uint32_t *kh, uint32_t *km, uint16_t *kl, uint8_t r) {
    uint32_t h = *kh, m = *km;
    uint32_t nh = (h >> 19) | ((uint32_t)*kl << 13) | (m << 29);
    uint32_t nm = (m >> 19) | (h << 13);
    uint16_t nl = (uint16_t)(m >> 3);

    nh = (nh & 0x0FFFFFFFu) | ((uint32_t)sbox[nh >> 28] << 28);
    nm ^= r >> 1;
    nl ^= (uint16_t)((r & 1u) << 15);
    *kh = nh;
    *km = nm;
    *kl = nl;
}

static void key_prev(uint32_t *kh, uint32_t *km, uint16_t *kl, uint8_t r) {
    uint32_t h = *kh, m = *km;
    uint16_t l = *kl;

    m ^= r >> 1;
    l ^= (uint16_t)((r & 1u) << 15);
    h = (h & 0x0FFFFFFFu) | ((uint32_t)isbox[h >> 28] << 28);
    *kh = (h << 19) | (m >> 13);
    *km = (m << 19) | ((uint32_t)l << 3) | (h >> 29);
    *kl = (uint16_t)(h >> 13);
}

static uint32_t inv_sbox(uint32_t x) {
    uint32_t y = 0;
    for (uint8_t i = 0; i < 8; ++i) {
        y = (y >> 4) | ((uint32_t)isbox[x & 15u] << 28);
        x >>= 4;
    }
    return y;
}

static void inv_perm(uint32_t *hi, uint32_t *lo) {
    uint32_t a = *hi, b = *lo;
    uint32_t oh = a & 0x80000000u, ol = 0;

    for (uint8_t i = 0; i < 63; ++i) {
        uint32_t bit = i < 32 ? ((b >> i) & 1u) : ((a >> (i - 32u)) & 1u);
        if (!bit) continue;

        uint16_t pos = (uint16_t)i << 2;
        if (pos >= 63u) pos -= 63u;
        if (pos >= 63u) pos -= 63u;
        if (pos >= 63u) pos -= 63u;
        if (pos < 32u) ol |= 1u << pos;
        else oh |= 1u << (pos - 32u);
    }

    *hi = oh;
    *lo = ol;
}

static void present_decrypt(uint32_t *hi, uint32_t *lo) {
    uint32_t kh = PRESENT_KEY_HI, km = PRESENT_KEY_MID;
    uint16_t kl = PRESENT_KEY_LO;

    for (uint8_t r = 1; r <= 31; ++r) key_next(&kh, &km, &kl, r);
    *hi ^= kh;
    *lo ^= km;

    for (uint8_t r = 31; r > 0; --r) {
        key_prev(&kh, &km, &kl, r);
        inv_perm(hi, lo);
        *hi = inv_sbox(*hi);
        *lo = inv_sbox(*lo);
        *hi ^= kh;
        *lo ^= km;
    }
}

static uint16_t get_edge(uint8_t node, uint8_t slot) {
    if (node < 1u || node > 36u || slot > 3u) return 0;
    return graph[node - 1u][slot];
}

static uint8_t shortest_path(uint8_t start, uint8_t end, uint8_t path[40], uint8_t dist[36]) {
    uint8_t seen[5] = {0};
    uint8_t i, j, k, node, cur, best, cost, next;

    if (start < 1u || start > 36u || end < 1u || end > 36u) return 0;
    for (i = 0; i < 36; ++i) dist[i] = 255u;
    dist[start - 1u] = 0;

    for (i = 0; i < 36; ++i) {
        best = 255u;
        node = 0;
        for (j = 0; j < 36; ++j) {
            if (!(seen[j >> 3] & (uint8_t)(1u << (j & 7u))) && dist[j] < best) {
                best = dist[j];
                node = (uint8_t)(j + 1u);
            }
        }
        if (!node) break;
        seen[(node - 1u) >> 3] |= (uint8_t)(1u << ((node - 1u) & 7u));
        if (node == end) break;

        for (k = 0; k < 4; ++k) {
            uint16_t e = get_edge(node, k);
            if (!e) continue;
            next = (uint8_t)(e & 63u);
            cost = (uint8_t)(e >> 6);
            if (!(seen[(next - 1u) >> 3] & (uint8_t)(1u << ((next - 1u) & 7u)))) {
                uint16_t candidate = (uint16_t)best + cost;
                if (candidate < dist[next - 1u]) dist[next - 1u] = (uint8_t)candidate;
            }
        }
    }

    cur = end;
    i = 0;
    path[i++] = cur;
    while (cur != start && i < 40u) {
        best = dist[cur - 1u];
        for (k = 0; k < 4; ++k) {
            uint16_t e = get_edge(cur, k);
            if (!e) continue;
            next = (uint8_t)(e & 63u);
            cost = (uint8_t)(e >> 6);
            if (dist[next - 1u] != 255u && (uint16_t)dist[next - 1u] + cost == best) break;
        }
        if (k == 4u) return 0;
        cur = next;
        path[i++] = cur;
    }

    if (cur != start) return 0;
    for (j = 0; j < (i >> 1); ++j) {
        uint8_t t = path[j];
        path[j] = path[i - j - 1u];
        path[i - j - 1u] = t;
    }
    return i;
}

// ##############################################

// main function
int main(int argc, char const *argv[]) {

    #ifdef __linux__

        if (argc < 4) {
            _put_str("usage: ./Path_Planner_Dec <current_node> <next_node> <is_encrypted>\n");
            _put_str("       current_node     : where the bot is, e.g. 35 (the start box)\n");
            _put_str("       is_encrypted = 0 : next_node is a node number, e.g. 7\n");
            _put_str("       is_encrypted = 1 : next_node is the encrypted code, 16 hex digits\n");
            return 1;
        }
        uint8_t  CURRENT_NODE        = atoi(argv[1]);
        uint8_t  IS_ENCRYPTED        = atoi(argv[3]);
        uint8_t  NEXT_NODE           = 0;
        uint32_t ENCRYPTED_HI        = 0;
        uint32_t ENCRYPTED_LO        = 0;
        if (IS_ENCRYPTED) {
            if (!read_block(argv[2], &ENCRYPTED_HI, &ENCRYPTED_LO)) {
                _put_str("with is_encrypted = 1, next_node must be exactly 16 hex digits\n");
                return 1;
            }
        }
        else {
            NEXT_NODE = atoi(argv[2]);
        }
        uint8_t MESSAGE_0           = 0;
        uint8_t MESSAGE_1           = 0;
        uint8_t MESSAGE_2           = 0;
        uint8_t MESSAGE_3           = 0;
        uint8_t MESSAGE_4           = 0;
        uint8_t NODE_POINT          = 0;
        uint8_t CPU_DONE            = 0;

    #else
        // Address value of variables are updated for RISC-V Implementation
        // inputs: 0x02000000 .. 0x0200000F
        #define ENCRYPTED_HI        (* (volatile uint32_t * ) 0x02000000)
        #define ENCRYPTED_LO        (* (volatile uint32_t * ) 0x02000004)
        #define IS_ENCRYPTED        (* (volatile uint8_t  * ) 0x02000008)
        #define NEXT_NODE           (* (volatile uint8_t  * ) 0x0200000c)
        #define CURRENT_NODE        (* (volatile uint8_t  * ) 0x0200000d)
        // outputs: 0x02000010 .. 0x0200001F
        #define MESSAGE_0           (* (volatile uint8_t  * ) 0x02000010)
        #define MESSAGE_1           (* (volatile uint8_t  * ) 0x02000011)
        #define MESSAGE_2           (* (volatile uint8_t  * ) 0x02000012)
        #define MESSAGE_3           (* (volatile uint8_t  * ) 0x02000013)
        #define MESSAGE_4           (* (volatile uint8_t  * ) 0x02000014)
        #define NODE_POINT          (* (volatile uint8_t  * ) 0x02000018)
        #define CPU_DONE            (* (volatile uint8_t  * ) 0x0200001c)

    #endif

    // read once here: for the next run, the program may write IS_ENCRYPTED = 0
    uint8_t is_encrypted = IS_ENCRYPTED;

    // the message: bytes 1..5 of the decrypted block (0x00 = no character)
    uint8_t message[5] = { 0, 0, 0, 0, 0 };

    // array to store the planned path
    uint8_t path_planned[40];
    // index to keep track of the path_planned array
    uint8_t idx = 0;

    uint8_t start_point = CURRENT_NODE;   // where the bot is
    uint8_t end_point   = 0;              // where the bot goes

    // ############# Add your code here #############
#ifdef __linux__
    uint8_t dist[36];
#else
    uint8_t *dist = (uint8_t *)0x02000020u;
#endif

    uint8_t done = 1;
    if (start_point < 1u || start_point > 36u) return 1;

    if (is_encrypted) {
        uint32_t block_hi = ENCRYPTED_HI;
        uint32_t block_lo = ENCRYPTED_LO;
        present_decrypt(&block_hi, &block_lo);

        done = (uint8_t)(block_hi >> 24);
        message[0] = (uint8_t)(block_hi >> 16);
        message[1] = (uint8_t)(block_hi >> 8);
        message[2] = (uint8_t)block_hi;
        message[3] = (uint8_t)(block_lo >> 24);
        message[4] = (uint8_t)(block_lo >> 16);
        end_point = (uint8_t)block_lo;

        if (done > 1u || end_point < 1u || end_point > 36u) return 1;
        if (!done) {
            uint8_t next = (uint8_t)(block_lo >> 8);
            if (next < 1u || next > 36u) return 1;
            IS_ENCRYPTED = 0;
            CURRENT_NODE = end_point;
            NEXT_NODE = next;
        }
    } else {
        end_point = NEXT_NODE;
        if (end_point < 1u || end_point > 36u) return 1;
    }

    idx = shortest_path(start_point, end_point, path_planned, dist);
    if (!idx) return 1;
);

    // ##############################################

    // the message bytes are written into data memory (encrypted block only).
    if (is_encrypted) {
        MESSAGE_0 = message[0];
        MESSAGE_1 = message[1];
        MESSAGE_2 = message[2];
        MESSAGE_3 = message[3];
        MESSAGE_4 = message[4];
    }
    // the node values are written into data memory sequentially.
    for (int i = 0; i < idx; ++i) {
        NODE_POINT = path_planned[i];
    }
    // Path Planning Computation Done Flag
    CPU_DONE = 1;

    #ifdef __linux__    // for host pc: the output test.sh reads (see "Output (PC)" at the top)

        if (is_encrypted) {
            _put_str("Message : ");
            for (int i = 0; i < 5; ++i) {
                if (message[i]) _put_byte(message[i]);
            }
            _put_byte('\n');
        }
        for (int i = 0; i < idx; ++i) {
            _put_value(path_planned[i]);
        }
        if (is_encrypted) {
            if (IS_ENCRYPTED == 0) {            // the inputs written for the next run
                _put_str("Next current_node : ");
                _put_value(CURRENT_NODE);
                _put_str("Next next_node : ");
                _put_value(NEXT_NODE);
            }
            else {
                _put_str("Done\n");
            }
        }

    #endif

    return 0;
}
