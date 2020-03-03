//======================================================================
//
// aes_key_mem.v
// -------------
// The AES key memory including round key generator.
//
//
// Author: Joachim Strombergson
// Copyright (c) 2013 Secworks Sweden AB
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or
// without modification, are permitted provided that the following
// conditions are met:
//
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in
//    the documentation and/or other materials provided with the
//    distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
// FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
// COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
// INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
// BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
// ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
//======================================================================

module aes_key_mem(
                   input wire            clk,
                   input wire            reset_n,

                   input wire [255 : 0]  key,
                   input wire            keylen,
                   input wire            init_key,
                   input wire            next_key,

                   output wire [127 : 0] round_key
                  );


  //----------------------------------------------------------------
  // Parameters.
  //----------------------------------------------------------------
  localparam AES_128_BIT_KEY = 1'h0;
  localparam AES_256_BIT_KEY = 1'h1;


  //----------------------------------------------------------------
  // Registers.
  //----------------------------------------------------------------
  reg [127 : 0] prev_key0_reg;
  reg [127 : 0] prev_key0_new;
  reg           prev_key0_we;

  reg [127 : 0] prev_key1_reg;
  reg [127 : 0] prev_key1_new;
  reg           prev_key1_we;

  reg [127 : 0] round_key_reg;
  reg [127 : 0] round_key_new;
  reg           round_key_we;

  reg [3 : 0] round_ctr_reg;
  reg [3 : 0] round_ctr_new;
  reg         round_ctr_rst;
  reg         round_ctr_inc;
  reg         round_ctr_we;

  reg [7 : 0] rcon_reg;
  reg [7 : 0] rcon_new;
  reg         rcon_we;
  reg         rcon_set;
  reg         rcon_next;


  //----------------------------------------------------------------
  // Functions.
  //----------------------------------------------------------------
  function [7 : 0] sb(input [7 : 0] x);
    case(x)
      8'h00: sb = 8'h63;
      8'h01: sb = 8'h7c;
      8'h02: sb = 8'h77;
      8'h03: sb = 8'h7b;
      8'h04: sb = 8'hf2;
      8'h05: sb = 8'h6b;
      8'h06: sb = 8'h6f;
      8'h07: sb = 8'hc5;
      8'h08: sb = 8'h30;
      8'h09: sb = 8'h01;
      8'h0a: sb = 8'h67;
      8'h0b: sb = 8'h2b;
      8'h0c: sb = 8'hfe;
      8'h0d: sb = 8'hd7;
      8'h0e: sb = 8'hab;
      8'h0f: sb = 8'h76;
      8'h10: sb = 8'hca;
      8'h11: sb = 8'h82;
      8'h12: sb = 8'hc9;
      8'h13: sb = 8'h7d;
      8'h14: sb = 8'hfa;
      8'h15: sb = 8'h59;
      8'h16: sb = 8'h47;
      8'h17: sb = 8'hf0;
      8'h18: sb = 8'had;
      8'h19: sb = 8'hd4;
      8'h1a: sb = 8'ha2;
      8'h1b: sb = 8'haf;
      8'h1c: sb = 8'h9c;
      8'h1d: sb = 8'ha4;
      8'h1e: sb = 8'h72;
      8'h1f: sb = 8'hc0;
      8'h20: sb = 8'hb7;
      8'h21: sb = 8'hfd;
      8'h22: sb = 8'h93;
      8'h23: sb = 8'h26;
      8'h24: sb = 8'h36;
      8'h25: sb = 8'h3f;
      8'h26: sb = 8'hf7;
      8'h27: sb = 8'hcc;
      8'h28: sb = 8'h34;
      8'h29: sb = 8'ha5;
      8'h2a: sb = 8'he5;
      8'h2b: sb = 8'hf1;
      8'h2c: sb = 8'h71;
      8'h2d: sb = 8'hd8;
      8'h2e: sb = 8'h31;
      8'h2f: sb = 8'h15;
      8'h30: sb = 8'h04;
      8'h31: sb = 8'hc7;
      8'h32: sb = 8'h23;
      8'h33: sb = 8'hc3;
      8'h34: sb = 8'h18;
      8'h35: sb = 8'h96;
      8'h36: sb = 8'h05;
      8'h37: sb = 8'h9a;
      8'h38: sb = 8'h07;
      8'h39: sb = 8'h12;
      8'h3a: sb = 8'h80;
      8'h3b: sb = 8'he2;
      8'h3c: sb = 8'heb;
      8'h3d: sb = 8'h27;
      8'h3e: sb = 8'hb2;
      8'h3f: sb = 8'h75;
      8'h40: sb = 8'h09;
      8'h41: sb = 8'h83;
      8'h42: sb = 8'h2c;
      8'h43: sb = 8'h1a;
      8'h44: sb = 8'h1b;
      8'h45: sb = 8'h6e;
      8'h46: sb = 8'h5a;
      8'h47: sb = 8'ha0;
      8'h48: sb = 8'h52;
      8'h49: sb = 8'h3b;
      8'h4a: sb = 8'hd6;
      8'h4b: sb = 8'hb3;
      8'h4c: sb = 8'h29;
      8'h4d: sb = 8'he3;
      8'h4e: sb = 8'h2f;
      8'h4f: sb = 8'h84;
      8'h50: sb = 8'h53;
      8'h51: sb = 8'hd1;
      8'h52: sb = 8'h00;
      8'h53: sb = 8'hed;
      8'h54: sb = 8'h20;
      8'h55: sb = 8'hfc;
      8'h56: sb = 8'hb1;
      8'h57: sb = 8'h5b;
      8'h58: sb = 8'h6a;
      8'h59: sb = 8'hcb;
      8'h5a: sb = 8'hbe;
      8'h5b: sb = 8'h39;
      8'h5c: sb = 8'h4a;
      8'h5d: sb = 8'h4c;
      8'h5e: sb = 8'h58;
      8'h5f: sb = 8'hcf;
      8'h60: sb = 8'hd0;
      8'h61: sb = 8'hef;
      8'h62: sb = 8'haa;
      8'h63: sb = 8'hfb;
      8'h64: sb = 8'h43;
      8'h65: sb = 8'h4d;
      8'h66: sb = 8'h33;
      8'h67: sb = 8'h85;
      8'h68: sb = 8'h45;
      8'h69: sb = 8'hf9;
      8'h6a: sb = 8'h02;
      8'h6b: sb = 8'h7f;
      8'h6c: sb = 8'h50;
      8'h6d: sb = 8'h3c;
      8'h6e: sb = 8'h9f;
      8'h6f: sb = 8'ha8;
      8'h70: sb = 8'h51;
      8'h71: sb = 8'ha3;
      8'h72: sb = 8'h40;
      8'h73: sb = 8'h8f;
      8'h74: sb = 8'h92;
      8'h75: sb = 8'h9d;
      8'h76: sb = 8'h38;
      8'h77: sb = 8'hf5;
      8'h78: sb = 8'hbc;
      8'h79: sb = 8'hb6;
      8'h7a: sb = 8'hda;
      8'h7b: sb = 8'h21;
      8'h7c: sb = 8'h10;
      8'h7d: sb = 8'hff;
      8'h7e: sb = 8'hf3;
      8'h7f: sb = 8'hd2;
      8'h80: sb = 8'hcd;
      8'h81: sb = 8'h0c;
      8'h82: sb = 8'h13;
      8'h83: sb = 8'hec;
      8'h84: sb = 8'h5f;
      8'h85: sb = 8'h97;
      8'h86: sb = 8'h44;
      8'h87: sb = 8'h17;
      8'h88: sb = 8'hc4;
      8'h89: sb = 8'ha7;
      8'h8a: sb = 8'h7e;
      8'h8b: sb = 8'h3d;
      8'h8c: sb = 8'h64;
      8'h8d: sb = 8'h5d;
      8'h8e: sb = 8'h19;
      8'h8f: sb = 8'h73;
      8'h90: sb = 8'h60;
      8'h91: sb = 8'h81;
      8'h92: sb = 8'h4f;
      8'h93: sb = 8'hdc;
      8'h94: sb = 8'h22;
      8'h95: sb = 8'h2a;
      8'h96: sb = 8'h90;
      8'h97: sb = 8'h88;
      8'h98: sb = 8'h46;
      8'h99: sb = 8'hee;
      8'h9a: sb = 8'hb8;
      8'h9b: sb = 8'h14;
      8'h9c: sb = 8'hde;
      8'h9d: sb = 8'h5e;
      8'h9e: sb = 8'h0b;
      8'h9f: sb = 8'hdb;
      8'ha0: sb = 8'he0;
      8'ha1: sb = 8'h32;
      8'ha2: sb = 8'h3a;
      8'ha3: sb = 8'h0a;
      8'ha4: sb = 8'h49;
      8'ha5: sb = 8'h06;
      8'ha6: sb = 8'h24;
      8'ha7: sb = 8'h5c;
      8'ha8: sb = 8'hc2;
      8'ha9: sb = 8'hd3;
      8'haa: sb = 8'hac;
      8'hab: sb = 8'h62;
      8'hac: sb = 8'h91;
      8'had: sb = 8'h95;
      8'hae: sb = 8'he4;
      8'haf: sb = 8'h79;
      8'hb0: sb = 8'he7;
      8'hb1: sb = 8'hc8;
      8'hb2: sb = 8'h37;
      8'hb3: sb = 8'h6d;
      8'hb4: sb = 8'h8d;
      8'hb5: sb = 8'hd5;
      8'hb6: sb = 8'h4e;
      8'hb7: sb = 8'ha9;
      8'hb8: sb = 8'h6c;
      8'hb9: sb = 8'h56;
      8'hba: sb = 8'hf4;
      8'hbb: sb = 8'hea;
      8'hbc: sb = 8'h65;
      8'hbd: sb = 8'h7a;
      8'hbe: sb = 8'hae;
      8'hbf: sb = 8'h08;
      8'hc0: sb = 8'hba;
      8'hc1: sb = 8'h78;
      8'hc2: sb = 8'h25;
      8'hc3: sb = 8'h2e;
      8'hc4: sb = 8'h1c;
      8'hc5: sb = 8'ha6;
      8'hc6: sb = 8'hb4;
      8'hc7: sb = 8'hc6;
      8'hc8: sb = 8'he8;
      8'hc9: sb = 8'hdd;
      8'hca: sb = 8'h74;
      8'hcb: sb = 8'h1f;
      8'hcc: sb = 8'h4b;
      8'hcd: sb = 8'hbd;
      8'hce: sb = 8'h8b;
      8'hcf: sb = 8'h8a;
      8'hd0: sb = 8'h70;
      8'hd1: sb = 8'h3e;
      8'hd2: sb = 8'hb5;
      8'hd3: sb = 8'h66;
      8'hd4: sb = 8'h48;
      8'hd5: sb = 8'h03;
      8'hd6: sb = 8'hf6;
      8'hd7: sb = 8'h0e;
      8'hd8: sb = 8'h61;
      8'hd9: sb = 8'h35;
      8'hda: sb = 8'h57;
      8'hdb: sb = 8'hb9;
      8'hdc: sb = 8'h86;
      8'hdd: sb = 8'hc1;
      8'hde: sb = 8'h1d;
      8'hdf: sb = 8'h9e;
      8'he0: sb = 8'he1;
      8'he1: sb = 8'hf8;
      8'he2: sb = 8'h98;
      8'he3: sb = 8'h11;
      8'he4: sb = 8'h69;
      8'he5: sb = 8'hd9;
      8'he6: sb = 8'h8e;
      8'he7: sb = 8'h94;
      8'he8: sb = 8'h9b;
      8'he9: sb = 8'h1e;
      8'hea: sb = 8'h87;
      8'heb: sb = 8'he9;
      8'hec: sb = 8'hce;
      8'hed: sb = 8'h55;
      8'hee: sb = 8'h28;
      8'hef: sb = 8'hdf;
      8'hf0: sb = 8'h8c;
      8'hf1: sb = 8'ha1;
      8'hf2: sb = 8'h89;
      8'hf3: sb = 8'h0d;
      8'hf4: sb = 8'hbf;
      8'hf5: sb = 8'he6;
      8'hf6: sb = 8'h42;
      8'hf7: sb = 8'h68;
      8'hf8: sb = 8'h41;
      8'hf9: sb = 8'h99;
      8'hfa: sb = 8'h2d;
      8'hfb: sb = 8'h0f;
      8'hfc: sb = 8'hb0;
      8'hfd: sb = 8'h54;
      8'hfe: sb = 8'hbb;
      8'hff: sb = 8'h16;
    endcase // case (x)
  endfunction // sb

  function [31 : 0] sbox(input [31 : 0] xw);
    sbox = {sb(xw[31 : 24]), sb(xw[23 : 16]),
            sb(xw[15 : 08]), sb(xw[07 : 00])};
  endfunction // sbox


  //----------------------------------------------------------------
  // Concurrent assignments for ports.
  //----------------------------------------------------------------
  assign round_key = round_key_reg;


  //----------------------------------------------------------------
  // reg_update
  //
  // Update functionality for all registers in the core.
  // All registers are positive edge triggered with asynchronous
  // active low reset. All registers have write enable.
  //----------------------------------------------------------------
  always @ (posedge clk or negedge reset_n)
    begin: reg_update
      if (!reset_n)
        begin
          rcon_reg         <= 8'h0;
          round_ctr_reg    <= 4'h0;
          prev_key0_reg    <= 128'h0;
          prev_key1_reg    <= 128'h0;
          round_key_reg    <= 128'h0;
        end
      else
        begin
          if (round_ctr_we)
            round_ctr_reg <= round_ctr_new;

          if (rcon_we)
            rcon_reg <= rcon_new;

          if (prev_key0_we)
            prev_key0_reg <= prev_key0_new;

          if (prev_key1_we)
            prev_key1_reg <= prev_key1_new;

          if (round_key_we)
            round_key_reg <= round_key_new;
        end
    end // reg_update


  //----------------------------------------------------------------
  // round_key_gen
  //
  // The round key generator logic for AES-128 and AES-256.
  //----------------------------------------------------------------
  always @*
    begin: round_key_gen
      reg [31 : 0] w0, w1, w2, w3, w4, w5, w6, w7;
      reg [31 : 0] k0, k1, k2, k3;
      reg [31 : 0] rconw, new_sboxw, rotstw, tw, trw;

      prev_key0_new = 128'h0;
      prev_key0_we  = 1'h0;
      prev_key1_new = 128'h0;
      prev_key1_we  = 1'h0;
      round_key_new = 128'h0;
      round_key_we  = 1'h0;
      k0            = 32'h0;
      k1            = 32'h0;
      k2            = 32'h0;
      k3            = 32'h0;
      rcon_next     = 1'h0;
      rcon_set      = 1'h0;
      round_ctr_rst = 1'h0;
      round_ctr_inc = 1'h0;

      // Extract words and calculate intermediate values.
      // Perform rotation of sbox word etc.
      w0 = prev_key0_reg[127 : 096];
      w1 = prev_key0_reg[095 : 064];
      w2 = prev_key0_reg[063 : 032];
      w3 = prev_key0_reg[031 : 000];

      w4 = prev_key1_reg[127 : 096];
      w5 = prev_key1_reg[095 : 064];
      w6 = prev_key1_reg[063 : 032];
      w7 = prev_key1_reg[031 : 000];

      rconw = {rcon_reg, 24'h0};
      new_sboxw = sbox(w7);
      tw = new_sboxw;
      rotstw = {new_sboxw[23 : 00], new_sboxw[31 : 24]};
      trw = rotstw ^ rconw;


      if (init_key)
        begin
          rcon_set      = 1'h1;
          prev_key0_new = 128'h0;
          prev_key0_we  = 1'h1;
          prev_key1_new = 128'h0;
          prev_key1_we  = 1'h1;
          round_key_new = 128'h0;
          round_key_we  = 1'h1;
          round_ctr_rst = 1'h1;
        end


      if (next_key)
        begin
          round_key_we  = 1'h1;
          round_ctr_inc = 1'h1;

          if (keylen == AES_128_BIT_KEY)
            begin
              if (round_ctr_reg == 0)
                begin
                  round_key_new = key[255 : 128];
                  prev_key1_new = key[255 : 128];
                  prev_key1_we  = 1'b1;
                  rcon_next     = 1'b1;
                end
              else
                begin
                  k0 = w4 ^ trw;
                  k1 = w5 ^ w4 ^ trw;
                  k2 = w6 ^ w5 ^ w4 ^ trw;
                  k3 = w7 ^ w6 ^ w5 ^ w4 ^ trw;

                  round_key_new = {k0, k1, k2, k3};
                  prev_key1_new = {k0, k1, k2, k3};
                  prev_key1_we  = 1'b1;
                  rcon_next     = 1'b1;
                end
            end

          else
            begin
              // AES_256_BIT_KEY
              if (round_ctr_reg == 0)
                begin
                  round_key_new = key[255 : 128];
                  prev_key0_new = key[255 : 128];
                  prev_key0_we  = 1'b1;
                end
              else if (round_ctr_reg == 1)
                begin
                  round_key_new = key[127 : 0];
                  prev_key1_new = key[127 : 0];
                  prev_key1_we  = 1'b1;
                  rcon_next     = 1'b1;
                end
              else
                begin
                  if (round_ctr_reg[0] == 0)
                    begin
                      k0 = w0 ^ trw;
                      k1 = w1 ^ w0 ^ trw;
                      k2 = w2 ^ w1 ^ w0 ^ trw;
                      k3 = w3 ^ w2 ^ w1 ^ w0 ^ trw;
                    end
                  else
                    begin
                      k0 = w0 ^ tw;
                      k1 = w1 ^ w0 ^ tw;
                      k2 = w2 ^ w1 ^ w0 ^ tw;
                      k3 = w3 ^ w2 ^ w1 ^ w0 ^ tw;
                      rcon_next = 1'b1;
                    end

                  // Store the generated round keys.
                  round_key_new = {k0, k1, k2, k3};
                  prev_key1_new = {k0, k1, k2, k3};
                  prev_key1_we  = 1'b1;
                  prev_key0_new = prev_key1_reg;
                  prev_key0_we  = 1'b1;
                end
            end
        end
    end // round_key_gen


  //----------------------------------------------------------------
  // rcon_logic
  //
  // Caclulates the rcon value for the different key expansion
  // iterations.
  //----------------------------------------------------------------
  always @*
    begin : rcon_logic
      reg [7 : 0] tmp_rcon;
      rcon_new = 8'h00;
      rcon_we  = 1'b0;

      tmp_rcon = {rcon_reg[6 : 0], 1'b0} ^ (8'h1b & {8{rcon_reg[7]}});

      if (rcon_set)
        begin
          rcon_new = 8'h8d;
          rcon_we  = 1'b1;
        end

      if (rcon_next)
        begin
          rcon_new = tmp_rcon[7 : 0];
          rcon_we  = 1'b1;
        end
    end


  //----------------------------------------------------------------
  // round_ctr
  //
  // The round counter logic with increase and reset.
  //----------------------------------------------------------------
  always @*
    begin : round_ctr
      round_ctr_new = 4'h0;
      round_ctr_we  = 1'b0;

      if (round_ctr_rst)
        begin
          round_ctr_new = 4'h0;
          round_ctr_we  = 1'b1;
        end

      else if (round_ctr_inc)
        begin
          round_ctr_new = round_ctr_reg + 1'b1;
          round_ctr_we  = 1'b1;
        end
    end

endmodule // aes_key_mem

//======================================================================
// EOF aes_key_mem.v
//======================================================================
