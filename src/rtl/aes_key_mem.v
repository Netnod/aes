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

                   output wire [127 : 0] round_key,
                   output wire           ready
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

  reg [2 : 0] key_mem_ctrl_reg;
  reg [2 : 0] key_mem_ctrl_new;
  reg         key_mem_ctrl_we;

  reg [7 : 0] rcon_reg;
  reg [7 : 0] rcon_new;
  reg         rcon_we;
  reg         rcon_set;
  reg         rcon_next;


  //----------------------------------------------------------------
  // Wires.
  //----------------------------------------------------------------
  reg [31 : 0]  keymem_sboxw;
  wire [31 : 0] new_keymem_sboxw;
  reg           round_key_update;
  reg [127 : 0] tmp_round_key;


  //----------------------------------------------------------------
  // Sbox instantiations.
  //----------------------------------------------------------------
  aes_sbox sbox_inst0(.sboxw(keymem_sboxw), .new_sboxw(new_keymem_sboxw));


  //----------------------------------------------------------------
  // Concurrent assignments for ports.
  //----------------------------------------------------------------
  assign round_key = round_key_reg;
  assign ready     = 1'h1;


  //----------------------------------------------------------------
  // reg_update
  //
  // Update functionality for all registers in the core.
  // All registers are positive edge triggered with asynchronous
  // active low reset. All registers have write enable.
  //----------------------------------------------------------------
  always @ (posedge clk or negedge reset_n)
    begin: reg_update
      integer i;

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
      reg [31 : 0] rconw, rotstw, tw, trw;

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
      keymem_sboxw = w7;
      rotstw = {new_keymem_sboxw[23 : 00], new_keymem_sboxw[31 : 24]};
      trw = rotstw ^ rconw;
      tw = new_keymem_sboxw;


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
