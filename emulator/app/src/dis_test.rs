// Licensed under the Apache-2.0 license

#[cfg(test)]
mod test {
    use crate::dis::*;

    #[test]
    fn test_addi() {
        let dis = disasm_inst(RvIsa::Rv32, 4, 0x10018193);
        assert_eq!(dis, "10018193          addi          gp,gp,256");
    }

    #[test]
    fn test_rand() {
        for test in TESTS.iter() {
            let dis = disasm_inst(test.isa, test.pc, test.inst);
            assert_eq!(dis.trim(), test.dis);
        }
    }

    struct Test {
        isa: RvIsa,
        pc: u64,
        inst: u64,
        dis: &'static str,
    }

    const TESTS: [Test; 46] = [
    Test {
        isa: RvIsa::Rv32,
        pc: 0xa49c6bb2d05fd8f0,
        inst: 0x807da997cfd1e0c0,
        dis: "e0c0              fsw           fs0,4(s1)",
    },
    Test {
        isa: RvIsa::Rv32,
        pc: 0x20d23164a27578e0,
        inst: 0x9aa12527300a282,
        dis: "a282              fsd           ft0,320(sp)",
    },
    Test {
        isa: RvIsa::Rv32,
        pc: 0x39dd7154ecb2f74b,
        inst: 0xfd0600206f5f1739,
        dis: "1739              addi          a4,a4,-18",
    },
    Test {
        isa: RvIsa::Rv32,
        pc: 0x544f7bacc793d0d9,
        inst: 0x7431e67ce97df08a,
        dis: "f08a              fsw           ft2,96(sp)",
    },
    Test {
        isa: RvIsa::Rv32,
        pc: 0x4c7e71b65f581e4b,
        inst: 0xb92d48b99d1e0e9d,
        dis: "0e9d              addi          t4,t4,7",
    },
    Test {
        isa: RvIsa::Rv32,
        pc: 0x59ea7883a2bced11,
        inst: 0xad5f81c850866194,
        dis: "6194              flw           fa3,0(a1)",
    },
    Test {
        isa: RvIsa::Rv32,
        pc: 0x5993992291379bfa,
        inst: 0x4fd118d276b58090,
        dis: "8090              illegal",
    },
    Test {
        isa: RvIsa::Rv32,
        pc: 0x223d81bbfc99de86,
        inst: 0xb22340e0f071ef5d,
        dis: "ef5d              bnez          a4,190                          # 0x223d81bbfc99df44",
    },
    Test {
        isa: RvIsa::Rv32,
        pc: 0xf5e52b8c386511ee,
        inst: 0xc5b957dc8d74ca08,
        dis: "ca08              sw            a0,16(a2)",
    },
    Test {
        isa: RvIsa::Rv32,
        pc: 0xf3037aae5fbb221b,
        inst: 0xad13dac1351a8591,
        dis: "8591              srai          a1,a1,4",
    },
    Test {
        isa: RvIsa::Rv32,
        pc: 0x8c53e4ef2f65cd37,
        inst: 0x9858a15935d7351b,
        dis: "35d7351b          illegal",
    },
    Test {
        isa: RvIsa::Rv32,
        pc: 0xba167b26d53ebaa6,
        inst: 0x9f8ea88d23f51e5a,
        dis: "1e5a              slli          t3,t3,54",
    },
    Test {
        isa: RvIsa::Rv32,
        pc: 0xbffff9c00aa727d1,
        inst: 0x429073849bce63d9,
        dis: "63d9              lui           t2,90112",
    },
    Test {
        isa: RvIsa::Rv64,
        pc: 0xbac446321c8eb13e,
        inst: 0x56e5c5e44b47d3e0,
        dis: "d3e0              sw            s0,100(a5)",
    },
    Test {
        isa: RvIsa::Rv64,
        pc: 0x6727f40fb54ab397,
        inst: 0x8dc61644a603b093,
        dis: "a603b093          sltiu         ra,t2,-1440",
    },
    Test {
        isa: RvIsa::Rv64,
        pc: 0xa850e711e3e9882b,
        inst: 0x165b1355444dc6c,
        dis: "dc6c              sw            a1,124(s0)",
    },
    Test {
        isa: RvIsa::Rv64,
        pc: 0xd6dc95f60c61be2b,
        inst: 0xbe7d58000ece4654,
        dis: "4654              lw            a3,12(a2)",
    },
    Test {
        isa: RvIsa::Rv64,
        pc: 0xdc2ae04109dc4195,
        inst: 0x9dda199f32e94e94,
        dis: "4e94              lw            a3,24(a3)",
    },
    Test {
        isa: RvIsa::Rv64,
        pc: 0x205612559b27aa2a,
        inst: 0xbde51120a5b33e22,
        dis: "3e22              fld           ft8,40(sp)",
    },
    Test {
        isa: RvIsa::Rv64,
        pc: 0x30ee5dc7262aaa98,
        inst: 0x236cda08f5936459,
        dis: "6459              lui           s0,90112",
    },
    Test {
        isa: RvIsa::Rv64,
        pc: 0xc2cd32ce81dea1ff,
        inst: 0x79ab8b7c5f947e05,
        dis: "7e05              lui           t3,-126976",
    },
    Test {
        isa: RvIsa::Rv64,
        pc: 0xb878a08831099b97,
        inst: 0x9c456a969d328de3,
        dis: "9d328de3          beq           t0,s3,-1574                     # 0xb878a08831099571",
    },
    Test {
        isa: RvIsa::Rv64,
        pc: 0xbeb8384efa1880a5,
        inst: 0xbd07b6b78927457b,
        dis: "8927457b          illegal",
    },
    Test {
        isa: RvIsa::Rv64,
        pc: 0xa936635de4e060,
        inst: 0xab7e0c01db063153,
        dis: "db063153          illegal",
    },
    Test {
        isa: RvIsa::Rv64,
        pc: 0x1a05c3870b250837,
        inst: 0xbbaea22393d901f,
        dis: "ea22393d901f      illegal",
    },
    Test {
        isa: RvIsa::Rv64,
        pc: 0x30bc578c5ef60df2,
        inst: 0xdc00462bb132a40,
        dis: "2a40              fld           fs0,144(a2)",
    },
    Test {
        isa: RvIsa::Rv64,
        pc: 0x5842e18db0eec572,
        inst: 0xdd3539935b45fd99,
        dis: "fd99              bnez          a1,-226                         # 0x5842e18db0eec490",
    },
    Test {
        isa: RvIsa::Rv64,
        pc: 0xaea089a9171156d4,
        inst: 0xbab8e8c52e0ff410,
        dis: "f410              sd            a2,40(s0)",
    },
    Test {
        isa: RvIsa::Rv64,
        pc: 0x40092daff0613508,
        inst: 0x2d5f4d2ac7a1e992,
        dis: "e992              sd            tp,208(sp)",
    },
    Test {
        isa: RvIsa::Rv64,
        pc: 0x39f92addc8a6a528,
        inst: 0x37a1b0bdb071a74b,
        dis: "b071a74b          fnmsub.s      rdn,fa4,ft3,ft7,fs6",
    },
    Test {
        isa: RvIsa::Rv64,
        pc: 0x8a2aa8021549a247,
        inst: 0xcfb52eb73a6b98d2,
        dis: "98d2              add           a7,a7,s4",
    },
    Test {
        isa: RvIsa::Rv64,
        pc: 0x29bc33617aa0e27e,
        inst: 0x83abe031b30f1aef,
        dis: "b30f1aef          jal           s5,-60624                       # 0x29bc33617a9ff5ae",
    },
    Test {
        isa: RvIsa::Rv64,
        pc: 0x1b25d299cdd61d0f,
        inst: 0x14d6baf36a6d8a4,
        dis: "d8a4              sw            s1,112(s1)",
    },
    Test {
        isa: RvIsa::Rv128,
        pc: 0x63a1076b2f8f8ddf,
        inst: 0xb5810041454b6808,
        dis: "6808              ld            a0,16(s0)",
    },
    Test {
        isa: RvIsa::Rv128,
        pc: 0xde37ed706b08f7d2,
        inst: 0x5905d2b10b8cc263,
        dis: "0b8cc263          blt           s9,s8,164                       # 0xde37ed706b08f876",
    },
    Test {
        isa: RvIsa::Rv128,
        pc: 0xfd93f334fd4310d4,
        inst: 0xedb8dca82ae722c0,
        dis: "22c0              lq            s0,128(a3)",
    },
    Test {
        isa: RvIsa::Rv128,
        pc: 0xf099b293cbdfa78b,
        inst: 0x3ee72fabfa5c14e7,
        dis: "fa5c14e7          illegal",
    },
    Test {
        isa: RvIsa::Rv128,
        pc: 0xb60fe937f2d8a5a5,
        inst: 0x8b1188a85f37d06e,
        dis: "d06e              sw            s11,32(sp)",
    },
    Test {
        isa: RvIsa::Rv128,
        pc: 0xa9d364e25e937cc,
        inst: 0xd11de68d93d2470c,
        dis: "470c              lw            a1,8(a4)",
    },
    Test {
        isa: RvIsa::Rv128,
        pc: 0xfb1265353347a48,
        inst: 0x45a9b2645f452431,
        dis: "2431              addiw         s0,s0,12",
    },
    Test {
        isa: RvIsa::Rv128,
        pc: 0xcefbbe830a6b81eb,
        inst: 0xd2361ae323054dc5,
        dis: "4dc5              li            s11,17",
    },
    Test {
        isa: RvIsa::Rv128,
        pc: 0x4163334dc328573,
        inst: 0x656c8f61fd55b237,
        dis: "fd55b237          lui           tp,-44716032",
    },
    Test {
        isa: RvIsa::Rv128,
        pc: 0x5504ddde952527a5,
        inst: 0xd7fd75c4e5093dbd,
        dis: "3dbd              addiw         s11,s11,-17",
    },
    Test {
        isa: RvIsa::Rv128,
        pc: 0x6e5c14bfc64dde30,
        inst: 0x5abbbd1afd751891,
        dis: "1891              addi          a7,a7,-28",
    },
    Test {
        isa: RvIsa::Rv128,
        pc: 0xfd2b39f8fc0b7b04,
        inst: 0xb979fbb5768ce9f3,
        dis: "768ce9f3          csrrsi        s3,0x768,25",
    },
    Test {
        isa: RvIsa::Rv128,
        pc: 0x54a85d6a124687fa,
        inst: 0xe323f57851458ed4,
        dis: "8ed4              illegal",
    },
];
}
