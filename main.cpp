#include <iostream>
#include <fstream>
#include <iomanip>
#include <string>
#include <vector>
#include <cstdio>
#include <map>
#include <cstddef>

using namespace std;

map<size_t, string> registers{
        {0,  "zero"},
        {1,  "ra"},
        {2,  "sp"},
        {3,  "gp"},
        {4,  "tp"},
        {5,  "t0"},
        {6,  "t1"},
        {7,  "t2"},
        {8,  "s0"},
        {9,  "s1"},
        {10, "a0"},
        {11, "a1"},
        {12, "a2"},
        {13, "a3"},
        {14, "a4"},
        {15, "a5"},
        {16, "a6"},
        {17, "a7"},
        {18, "s2"},
        {19, "s3"},
        {20, "s4"},
        {21, "s5"},
        {22, "s6"},
        {23, "s7"},
        {24, "s8"},
        {25, "s9"},
        {26, "s10"},
        {27, "s11"},
        {28, "t3"},
        {29, "t4"},
        {30, "t5"},
        {31, "t6"}
};

map<size_t, string> b_type{
        {0, "beq"},
        {1, "bne"},
        {4, "blt"},
        {5, "bge"},
        {6, "bltu"},
        {7, "bgeu"},
};

map<size_t, string> l_type{
        {0, "lb"},
        {1, "lh"},
        {2, "lw"},
        {4, "lbu"},
        {5, "lhu"},
};

map<size_t, string> s_type{
        {0, "sb"},
        {1, "sh"},
        {2, "sw"},
};


map<size_t, string> i_type{
        {0, "addi"},
        {2, "slti"},
        {3, "sltiu"},
        {4, "xori"},
        {6, "ori"},
        {7, "andi"},
};

map<pair<size_t, size_t>, string> r_type{
        {{0,  0}, "add"},
        {{32, 0}, "sub"},
        {{0,  1}, "sll"},
        {{0,  2}, "slt"},
        {{0,  3}, "sltu"},
        {{0,  4}, "xor"},
        {{0,  5}, "srl"},
        {{32, 5}, "sra"},
        {{0,  6}, "or"},
        {{0,  7}, "and"},
        {{1,  0}, "mul"},
        {{1,  1}, "mulh"},
        {{1,  2}, "mulhsu"},
        {{1,  3}, "mulhu"},
        {{1,  4}, "div"},
        {{1,  5}, "divu"},
        {{1,  6}, "rem"},
        {{1,  7}, "remu"},
};

map<size_t, string> symbol_types{
        {0,  "NOTYPE"},
        {1,  "OBJECT"},
        {2,  "FUNC"},
        {3,  "SECTION"},
        {4,  "FILE"},
        {5,  "COMMON"},
        {6,  "TLS"},
        {10, "LOOS"},
        {12, "HIOS"},
        {13, "LOPROC"},
        {14, "SPARC_REGISTER"},
        {15, "HIPROC"}
};

map<size_t, string> symbol_binds{
        {0,  "LOCAL"},
        {1,  "GLOBAL"},
        {2,  "WEAK"},
        {10, "LOOS"},
        {12, "HIOS"},
        {13, "LOPROC"},
        {15, "HIPROC"}
};

map<size_t, string> symbol_vises{
        {0, "DEFAULT"},
        {1, "INTERNAL"},
        {2, "HIDDEN"},
        {3, "PROTECTED"},
        {4, "EXPORTED"},
        {5, "SINGLETON"},
        {6, "ELIMINATE"}
};

map<size_t, string> symbol_idx{
        {0,      "UNDEF"},
        {0xff00, "BEFORE"},
        {0xff01, "AFTER"},
        {0xff02, "AMD64_LCOMMON"},
        {0xff1f, "HIPROC"},
        {0xff20, "LOOS"},
        {0xff3f, "HIOS"},
        {0xfff1, "ABS"},
        {0xfff2, "COMMON"},
        {0xffff, "XINDEX"}
};

size_t bytes_to_int(byte bytes[], size_t start, size_t end) {
    size_t ans = 0;
    for (size_t i = start; i < end; i++) {
        ans += ((size_t) bytes[i]) << (8 * (i - start));
    }
    return ans;
}

struct Header {
    size_t EI_MAG;
    size_t EI_CLASS;
    size_t EI_DATA;
    size_t EI_VERSION;
    size_t EI_OSABI;
    size_t EI_ABIVERSION;

    size_t e_type;
    size_t e_machine;
    size_t e_version;
    size_t e_entry;
    size_t e_phoff;
    size_t e_shoff;
    size_t e_flags;
    size_t e_ehsize;
    size_t e_phentsize;
    size_t e_phnum;
    size_t e_shentsize;
    size_t e_shnum;
    size_t e_shstrndx;
};

bool check_header(Header header) {
    if ((header.EI_MAG != 0x464c457f) || (header.EI_CLASS != 0x01) || (header.EI_DATA != 0x01) ||
        (header.EI_VERSION != 0x01) || (header.e_machine != 0xf3) || (header.e_version != 0x01) ||
        (header.e_shentsize != 0x28) || (header.e_ehsize != 0x34) || (header.e_shstrndx == 0)) {
        cerr << "Incorrect input file\n";
        return false;
    }
    return true;
}

Header make_header(byte bytes[]) {
    Header header{};
    header.EI_MAG = bytes_to_int(bytes, 0, 4);
    header.EI_CLASS = bytes_to_int(bytes, 4, 5);
    header.EI_DATA = bytes_to_int(bytes, 5, 6);
    header.EI_VERSION = bytes_to_int(bytes, 6, 7);
    header.EI_OSABI = bytes_to_int(bytes, 7, 8);
    header.EI_ABIVERSION = bytes_to_int(bytes, 8, 9);

    header.e_type = bytes_to_int(bytes, 16, 18);
    header.e_machine = bytes_to_int(bytes, 18, 20);
    header.e_version = bytes_to_int(bytes, 20, 24);
    header.e_entry = bytes_to_int(bytes, 24, 28);
    header.e_phoff = bytes_to_int(bytes, 28, 32);
    header.e_shoff = bytes_to_int(bytes, 32, 36);
    header.e_flags = bytes_to_int(bytes, 36, 40);
    header.e_ehsize = bytes_to_int(bytes, 40, 42);
    header.e_phentsize = bytes_to_int(bytes, 42, 44);
    header.e_phnum = bytes_to_int(bytes, 44, 46);
    header.e_shentsize = bytes_to_int(bytes, 46, 48);
    header.e_shnum = bytes_to_int(bytes, 48, 50);
    header.e_shstrndx = bytes_to_int(bytes, 50, 52);
    return header;
}

struct Section {
    string name;
    size_t sh_name{};

    size_t sh_type{};
    size_t sh_flags{};
    size_t sh_addr{};
    size_t sh_offset{};
    size_t sh_size{};
    size_t sh_link{};
    size_t sh_info{};
    size_t sh_addralign{};
    size_t sh_entsize{};
};

Section make_section(byte bytes[], size_t offset, size_t names_offset) {
    Section section{};
    section.sh_name = bytes_to_int(bytes + offset, 0, 4);
    section.name = "";
    for (int i = 0; (int) bytes[names_offset + section.sh_name + i] != 0; i++) {
        section.name += (char) bytes[names_offset + section.sh_name + i];
    }
    section.sh_type = bytes_to_int(bytes + offset, 4, 8);
    section.sh_flags = bytes_to_int(bytes + offset, 8, 12);
    section.sh_addr = bytes_to_int(bytes + offset, 12, 16);
    section.sh_offset = bytes_to_int(bytes + offset, 16, 20);
    section.sh_size = bytes_to_int(bytes + offset, 20, 24);
    section.sh_link = bytes_to_int(bytes + offset, 24, 28);
    section.sh_info = bytes_to_int(bytes + offset, 28, 32);
    section.sh_addralign = bytes_to_int(bytes + offset, 32, 36);
    section.sh_entsize = bytes_to_int(bytes + offset, 36, 40);
    return section;
}

struct Symbol {
    string name;
    string type;
    string bind;
    string vis;
    string index;

    size_t st_name{};
    size_t st_value{};
    size_t st_size{};
    size_t st_info{};
    size_t st_other{};
    size_t st_shndx{};
};

void make_symbol(Symbol *symbol, byte bytes[], size_t offset, size_t names_offset) {
    symbol->st_name = bytes_to_int(bytes + offset, 0, 4);
    symbol->name = "";
    for (int i = 0; (int) bytes[names_offset + symbol->st_name + i] != 0; i++) {
        symbol->name += (char) bytes[names_offset + symbol->st_name + i];
    }
    symbol->st_value = bytes_to_int(bytes + offset, 4, 8);
    symbol->st_size = bytes_to_int(bytes + offset, 8, 12);
    symbol->st_info = bytes_to_int(bytes + offset, 12, 13);
    symbol->st_other = bytes_to_int(bytes + offset, 13, 14);
    symbol->st_shndx = bytes_to_int(bytes + offset, 14, 16);

    symbol->type = symbol_types[symbol->st_info & 0xf];
    symbol->bind = symbol_binds[symbol->st_info >> 4];
    if (symbol_idx.count(symbol->st_shndx))
        symbol->index = symbol_idx[symbol->st_shndx];
    else
        symbol->index = to_string(symbol->st_shndx);
    symbol->vis = symbol_vises[symbol->st_other & 0x3];
}

enum instruction_type {
    unknown_instr,
    jal,
    arg1d,
    argdm,
    argd1m,
    arg12ml,
    argd12,
    argd1s,
    lsdm1,
    ls2m1,
    fence,
    empty_instr,
};

struct Instruction {
    string op_name = "unknown instruction";
    string rs1_name;
    string rs2_name;
    string rd_name;
    instruction_type type = unknown_instr;

    size_t imm{};
    size_t shamt{};

    size_t data{};
    size_t opcode{};
    size_t rd{};
    size_t funct3{};
    size_t rs1{};
    size_t rs2{};
    size_t funct7{};
};

Instruction make_instruction(size_t data) {
    Instruction cur;
    cur.data = data;
    cur.opcode = data & 0b1111111;
    cur.rd = (data >> 7) & 0b11111;
    cur.funct3 = (data >> 12) & 0b111;
    cur.rs1 = (data >> 15) & 0b11111;
    cur.rs2 = (data >> 20) & 0b11111;
    cur.funct7 = (data >> 25) & 0b1111111;


    cur.rd_name = registers[cur.rd];
    cur.rs1_name = registers[cur.rs1];
    cur.rs2_name = registers[cur.rs2];

    switch (cur.opcode) {
        case 0b0110111:
            cur.op_name = "lui";
            cur.imm = cur.data >> 12;
            cur.type = argdm;
            break;
        case 0b0010111:
            cur.op_name = "auipc";
            cur.imm = cur.data >> 12;
            cur.type = argdm;
            break;
        case 0b1101111:
            cur.op_name = "jal";
            cur.imm = ((cur.data & (1 << 31)) >> 11) + (cur.rs1 << 15) + (cur.funct3 << 12) +
                      ((cur.rs2 & 1) << 11) + ((cur.rs2 >> 1) << 1) + ((cur.funct7 & 0b111111) << 5);
            if (cur.data & (1 << 31)) {
                cur.imm |= (int) 0xfffc0000;
            }
            cur.type = jal;
            break;
        case 0b1100111:
            cur.op_name = "jalr";
            cur.imm = cur.data >> 19;
            cur.type = lsdm1;
            break;
        case 0b1100011:
            cur.op_name = b_type[cur.funct3];
            cur.imm = (int) (((cur.funct7 & 0b1000000) << 5) + ((cur.rd & 1) << 10) + ((cur.funct7 & 0b111111) << 4) +
                             (cur.rd >> 1)) << 1;
            if (cur.funct7 & 0b1000000) {
                cur.imm |= (int) 0xffffe000;
            }
            cur.type = arg12ml;
            break;
        case 0b0000011:
            cur.op_name = l_type[cur.funct3];
            cur.imm = cur.data >> 20;
            cur.type = lsdm1;
            break;
        case 0b0100011:
            cur.op_name = s_type[cur.funct3];
            cur.imm = (cur.funct7 << 5) + cur.rd;
            cur.type = ls2m1;
            break;
        case 0b0010011:
            if (cur.funct3 == 0b101) {
                cur.op_name = cur.funct7 ? "srai" : "srli";
                cur.type = argd1s;
                cur.shamt = cur.rs2;
            } else if (cur.funct3 == 0b001) {
                cur.op_name = "slli";
                cur.type = argd1s;
                cur.shamt = cur.rs2;
            } else {
                cur.op_name = i_type[cur.funct3];
                cur.type = argd1m;
                cur.imm = cur.data >> 20;
                if (cur.imm & 2048) {
                    cur.imm |= 0xfffff000;
                }
            }
            break;
        case 0b0110011:
            cur.op_name = r_type[{cur.funct7, cur.funct3}];
            cur.type = argd12;
            break;
        case 0b0001111:
            cur.op_name = "unknown_instruction";
            cur.type = fence;
            break;
        case 0b1110011:
            if (cur.funct7 == 0) {
                cur.op_name = "ecall";
            } else {
                cur.op_name = "ebreak";
            }
            cur.type = empty_instr;
            break;
    }
    return cur;
}

map<size_t, string> symbol_dict;
int marker_idx = 0;

void set_new_marker(const Instruction &instruction, const size_t shift) {
    if (instruction.type == arg12ml || instruction.type == jal) {
        if (!symbol_dict.count(instruction.imm + shift)) {
            symbol_dict[instruction.imm + shift] = "L" + to_string(marker_idx++);
        }
    }
}

void print_instruction(const Instruction &instruction, const size_t shift) {
    if (symbol_dict.count(shift)) {
        printf("%08zx   <%s>:\n", shift, symbol_dict[shift].c_str());
    }
    printf("   %05zx:\t%08zx\t%7s\t", shift, instruction.data, instruction.op_name.c_str());
    if (instruction.type == arg1d) {
        printf("%s, %s\n",
               instruction.rd_name.c_str(),
               instruction.rs1_name.c_str());
    } else if (instruction.type == argdm) {
        printf("%s, 0x%zx\n",
               instruction.rd_name.c_str(),
               instruction.imm);
    } else if (instruction.type == argd1m) {
        printf("%s, %s, %d\n",
               instruction.rd_name.c_str(),
               instruction.rs1_name.c_str(),
               (int) instruction.imm);
    } else if (instruction.type == argd1s) {
        printf("%s, %s, %zd\n",
               instruction.rd_name.c_str(),
               instruction.rs1_name.c_str(),
               instruction.shamt);
    } else if (instruction.type == argd12) {
        printf("%s, %s, %s\n",
               instruction.rd_name.c_str(),
               instruction.rs1_name.c_str(),
               instruction.rs2_name.c_str());
    } else if (instruction.type == arg12ml) { // b-type
        printf("%s, %s, 0x%zx <%s>\n",
               instruction.rs1_name.c_str(),
               instruction.rs2_name.c_str(),
               instruction.imm + shift,
               symbol_dict[instruction.imm + shift].c_str());
    } else if (instruction.type == lsdm1) {
        printf("%s, %zd(%s)\n",
               instruction.rd_name.c_str(),
               instruction.imm,
               instruction.rs1_name.c_str());
    } else if (instruction.type == ls2m1) {
        printf("%s, %zd(%s)\n",
               instruction.rs2_name.c_str(),
               instruction.imm,
               instruction.rs1_name.c_str());
    } else if (instruction.type == jal) {
        printf("%s, 0x%zx <%s>\n",
               instruction.rd_name.c_str(),
               instruction.imm + shift,
               symbol_dict[instruction.imm + shift].c_str());
    } else {
        printf("\n");
    }
}

void print_symbol(vector<Symbol> symbols, const int i) {
    printf("[%4i] 0x%-15zX %5zu %-8s %-8s %-8s %6s %s\n", i,
           symbols[i].st_value,
           symbols[i].st_size,
           symbols[i].type.c_str(),
           symbols[i].bind.c_str(),
           symbols[i].vis.c_str(),
           symbols[i].index.c_str(),
           symbols[i].name.c_str());

}

int main(int argc, char **argv) {
    if (argc != 3) {
        cerr << "incorrect arg count\n";
        return 1;
    }

    FILE *input = fopen(argv[1], "rb");
    size_t file_len;

    if (input) {
        fseek(input, 0, SEEK_END);
        file_len = ftell(input);
        fseek(input, 0, SEEK_SET);
    } else {
        cerr << "can't open input file\n";
        return 1;
    }

    byte *bytes = (byte *) malloc(file_len);
    fread(bytes, 1, file_len, input);
    fclose(input);

    Header header = make_header(bytes);
    if (!check_header(header)) {
        free(bytes);
        cerr << "file is not supported\n";
        return 1;
    }

    size_t names_pointer = header.e_shoff + header.e_shentsize * header.e_shstrndx;
    size_t names_offset = bytes_to_int(bytes, names_pointer + 16, names_pointer + 20);

    vector<Section> sections(header.e_shnum);
    Section *symtab_section;
    Section *strtab_section;
    Section *text_section;

    for (int i = 1; i < header.e_shnum; i++) {
        sections[i] = make_section(bytes, header.e_shoff + i * header.e_shentsize, names_offset);
        if (sections[i].name == ".symtab") {
            symtab_section = &sections[i];
        }
        if (sections[i].name == ".strtab") {
            strtab_section = &sections[i];
        }
        if (sections[i].name == ".text") {
            text_section = &sections[i];
        }
    }

    vector<Symbol> symbols(symtab_section->sh_size);
    for (int i = 0; i * symtab_section->sh_entsize < symtab_section->sh_size; i++) {
        make_symbol(&symbols[i], bytes, symtab_section->sh_offset + i * symtab_section->sh_entsize,
                    strtab_section->sh_offset);
        if (symbols[i].type == "OBJECT" || symbols[i].type == "FUNC") {
            symbol_dict[symbols[i].st_value] = symbols[i].name;
        }
    }

    for (int i = 0; i * 4 < text_section->sh_size; i++) {
        size_t data = bytes_to_int(bytes + text_section->sh_offset + i * 4, 0, 4);
        Instruction instruction = make_instruction(data);
        set_new_marker(instruction, text_section->sh_addr + i * 4);
    }

    if (!freopen(argv[2], "wt", stdout)) {
        free(bytes);
        cerr << "can't open output file\n";
        return 1;
    }

    cout << ".text\n";
    for (int i = 0; i * 4 < text_section->sh_size; i++) {
        size_t data = bytes_to_int(bytes + text_section->sh_offset + i * 4, 0, 4);
        Instruction instruction = make_instruction(data);
        print_instruction(instruction, text_section->sh_addr + i * 4);
    }
    cout << "\n.symtab\n";
    printf("%6s %-17s %5s %-8s %-8s %-8s %6s %s\n", "Symbol", "Value", "Size", "Type", "Bind", "Vis", "Index", "Name");
    for (int i = 0; i * symtab_section->sh_entsize < symtab_section->sh_size; i++) {
        print_symbol(symbols, i);
    }
    free(bytes);
    fclose(stdout);
    return 0;
}
