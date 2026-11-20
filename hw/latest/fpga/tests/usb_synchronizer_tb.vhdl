-- Licensed under the Apache-2.0 license

library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;
use std.env.all;

entity usb_synchronizer_tb is
end entity;

architecture test of usb_synchronizer_tb is
  signal fsclk : std_logic := '0';
  signal hclk : std_logic := '0';
  signal reset_n : std_logic := '0';
  signal flags_in : std_logic_vector(5 downto 0) := (others => '0');
  signal flags_out : std_logic_vector(5 downto 0);
  signal nbytes_in, nbytes_out : std_logic_vector(9 downto 0);
  signal maxpacket_in, maxpacket_out : std_logic_vector(1 downto 0);
begin
  fsclk <= not fsclk after 8 ns;
  hclk <= not hclk after 5 ns;

  dut : entity work.usb_synchronizer
    generic map (C_ULPI_SUPPORT => true, C_UTMI_SUPPORT => false)
    port map (
      sieint_epinfo_req => '0',
      sieint_epinfo_epnr => (others => '0'),
      sieint_epinfo_epdir => '0',
      sieint_epinfo_setup => '0',
      epinfo_valid => open,
      sieint_epinfo_setup_received => '0',
      epinfo_active => flags_out(5),
      epinfo_disabled => flags_out(4),
      epinfo_toggle => flags_out(3),
      epinfo_stall => flags_out(2),
      epinfo_iso => flags_out(1),
      epinfo_ratefeedbackmode => flags_out(0),
      epinfo_nbytes => nbytes_out,
      epinfo_maxpacket => maxpacket_out,
      sieint_txdatafetched => '0',
      epinfo_txdata => open,
      epinfo_txdata_valid => open,
      sieint_rx_nbytes => (others => '0'),
      sieint_rxdata => (others => '0'),
      sieint_rxdatavalid => '0',
      sieint_endtransfer => '0',
      sieint_success => '0',
      sieint_error => '0',
      sieint_errortype => (others => '0'),
      sieint_sentNAK => '0',
      VBusDebounced => '0',
      pie_lowpower_n => '1',
      vbuscomp_on => open,
      chrg_vbus => open,
      dischrg_vbus => open,
      avalid => '0',
      sessend => '0',
      TM_IsoToggle => 0,
      RG_BUSReset => false,
      TM_Suspend => false,
      LPM_TM_Suspend => false,
      LPM_RW => false,
      phy_addr => open,
      phy_wdata => open,
      phy_rdata => (others => '0'),
      phy_write => open,
      phy_start => open,
      phy_mode => open,
      phy_endtoggle => '0',
      sync_usbreg_phy_test_mode_change => open,
      sync_usbreg_dev_connect => open,
      sync_usbreg_remotewakeup => open,
      sync_usbreg_lpmremotewakeup => open,
      sync_usbreg_pll_on => open,
      sync_usbreg_lpm_sup => open,
      sync_usbreg_lpm_hird_sw => open,
      sync_usbreg_lpm_nyet => open,
      pie_speed => (others => '0'),
      sieint_lpm_hird_hw => (others => '0'),
      usbreg_frame_number_toggle => '0',
      usbreg_frame_number => (others => '0'),
      pie_dev_selected => 0,
      sync_sieint_epinfo_req => open,
      sync_sieint_epinfo_epnr => open,
      sync_sieint_epinfo_epdir => open,
      sync_sieint_epinfo_setup => open,
      sync_sieint_setup_received => open,
      sync_VBusDebounced => open,
      usbreg_vbuscomp_on => '0',
      usbreg_chrg_vbus => '0',
      usbreg_dischrg_vbus => '0',
      sync_avalid => open,
      sync_sessend => open,
      epinfo_sync_valid => '1',
      epinfo_sync_active => flags_in(5),
      epinfo_sync_disabled => flags_in(4),
      epinfo_sync_toggle => flags_in(3),
      epinfo_sync_stall => flags_in(2),
      epinfo_sync_iso => flags_in(1),
      epinfo_sync_ratefeedbackmode => flags_in(0),
      epinfo_sync_nbytes => nbytes_in,
      epinfo_sync_maxpacket => maxpacket_in,
      sync_sieint_txdatafetched => open,
      epinfo_sync_txdata => (others => '0'),
      epinfo_sync_txdata_valid => '0',
      sync_sieint_rx_nbytes => open,
      sync_sieint_rxdata => open,
      sync_sieint_rxdatavalid => open,
      sync_sieint_endtransfer => open,
      sync_sieint_success => open,
      sync_sieint_error => open,
      sync_sieint_errortype => open,
      sync_sieint_sentNAK => open,
      sync_set_frameint => open,
      sync_busreset => open,
      sync_suspend => open,
      sync_lpm_suspend => open,
      sync_lpm_rw => open,
      usbreg_phy_addr => (others => '0'),
      usbreg_phy_wdata => (others => '0'),
      sync_phy_rdata => open,
      usbreg_phy_write => '0',
      usbreg_phy_start => '0',
      usbreg_phy_mode => '1',
      sync_phy_endtoggle => open,
      usbreg_phy_test_mode => (others => '0'),
      usbreg_dev_connect => '1',
      usbreg_remotewakeup => '0',
      usbreg_lpmremotewakeup => '0',
      usbreg_pll_on => '1',
      usbreg_lpm_sup => '0',
      usbreg_lpm_hird_sw => (others => '0'),
      usbreg_lpm_nyet => '0',
      sync_pie_speed => open,
      sync_sieint_lpm_hird_hw => open,
      sync_usbreg_frame_number => open,
      sync_pie_dev_selected => open,
      FsClk => fsclk,
      Reset_N => reset_n,
      hclk => hclk,
      hrstn => reset_n
    );

  stimulus : process
    procedure sample_metadata(
      flags : std_logic_vector(5 downto 0);
      nbytes : natural;
      maxpacket : std_logic_vector(1 downto 0)
    ) is
    begin
      wait until falling_edge(fsclk);
      flags_in <= flags;
      nbytes_in <= std_logic_vector(to_unsigned(nbytes, 10));
      maxpacket_in <= maxpacket;
      wait until rising_edge(fsclk);
      wait for 1 ns;
      assert flags_out = flags
        report "endpoint status did not sample on FsClk after reset" severity failure;
      assert unsigned(nbytes_out) = nbytes and maxpacket_out = maxpacket
        report "endpoint packet metadata did not sample on FsClk" severity failure;
    end procedure;
  begin
    nbytes_in <= (others => '0');
    maxpacket_in <= (others => '0');
    wait for 40 ns;
    reset_n <= '1';
    sample_metadata("100001", 18, "01");
    sample_metadata("011110", 511, "10");
    reset_n <= '0';
    wait for 1 ns;
    assert flags_out = "000000" and unsigned(nbytes_out) = 0 and maxpacket_out = "00"
      report "endpoint metadata reset failed" severity failure;
    wait for 16 ns;
    reset_n <= '1';
    sample_metadata("101010", 64, "11");
    report "PASS: endpoint metadata updates and reset recovery";
    finish;
  end process;
end architecture;
