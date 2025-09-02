// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.26;

import {Script, console} from "forge-std/Script.sol";
import "../src/MantiKey.sol";
import "forge-std/console.sol";

contract MantiKeyScript is Script {
    function setUp() public {}

    function run() public {
        uint256 privateKey = vm.envUint("DEV_PRIVATE_KEY");

        address account = vm.addr(privateKey);

        console.log("Account", account);
        console.log("Balance: ", address(account).balance);

        vm.startBroadcast(privateKey);

        address signer1Addr = vm.envAddress("SIGNER_1_ADDR");
        address signer2Addr = vm.envAddress("SIGNER_2_ADDR");
        address signer3Addr = vm.envAddress("SIGNER_3_ADDR");

        //Change them accordingly
        MantiKey theContract = new MantiKey([signer1Addr, signer2Addr, signer3Addr], 2);

        vm.stopBroadcast();
    }
}
