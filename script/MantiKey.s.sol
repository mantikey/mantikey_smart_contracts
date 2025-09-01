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

        //Change them accordingly
        MantiKey theContract = new MantiKey([0x75cd272dc35E2C79E4D79AE89533210F5B33ed55, 0x0de9bcCd8119877d924681A70F5f779f8eDd0B57, 0xc8dc7333A1532627A805e37186DbB1beB5b03539], 2);

        vm.stopBroadcast();
    }
}
