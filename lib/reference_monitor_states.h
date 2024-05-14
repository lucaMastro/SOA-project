/*
    2 bits: least relevants. The least relevant one is about filterning activity: 0 doesnt filter, 1 filter.
    The other one is about reconfiguration: 0 cannot reconfigure, 1 can
*/
#define OFF     0x0 // 00
#define ON      0x1 // 01
#define RECOFF  0x2 // 10
#define RECON   0x3 // 11
