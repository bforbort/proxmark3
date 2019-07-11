//-----------------------------------------------------------------------------
// Copyright (C) 2018 Merlok
// Copyright (C) 2018 drHatson
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// High frequency MIFARE  Plus commands
//-----------------------------------------------------------------------------

#include "cmdhfmfd.h"

#include <inttypes.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include "comms.h"
#include "cmdmain.h"
#include "util.h"
#include "ui.h"
#include "cmdhf14a.h"
#include "mifare.h"
#include "mifare/mifare4.h"
#include "mifare/mad.h"
#include "mifare/ndef.h"
#include "cliparser/cliparser.h"
#include "crypto/libpcrypto.h"
#include "emv/dump.h"

static const uint8_t DefaultKeyId[2] = {0x00, 0x00};
static const uint8_t DefaultKey[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

static int CmdHelp(const char *Cmd);

int CmdHFMFDesAuth(const char *cmd) {
	// TODO: Autoslect or take from cmd
	// This is my test card's UUID
	uint8_t uid[10] = {0x04, 0x6e, 0x22, 0x72, 0x63, 0x34, 0x80};
	uint8_t keyn[250] = {0};
	int keynlen = 0;
	uint8_t key[250] = {0};
	int keylen = 0;
	
	CLIParserInit("hf mfd auth",
		"Executes DES3 authentication command for Mifare DESFire card",
		"Usage:\n\thf mfd auth 0000 00000000000000000000000000000000 -> executes authentication\n"
			"\thf mfd auth 9003 FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF -v -> executes authentication and shows all the system data\n");

	void* argtable[] = {
		arg_param_begin,
		arg_lit0("vV",  "verbose", "show internal data."),
		arg_str1(NULL,  NULL,     "<Key Num (HEX 2 bytes)>", NULL),
		arg_str1(NULL,  NULL,     "<Key Value (HEX 16 bytes)>", NULL),
		arg_param_end
	};
	CLIExecWithReturn(cmd, argtable, true);
	
	bool verbose = arg_get_lit(1);
	CLIGetHexWithReturn(2, keyn, &keynlen);
	CLIGetHexWithReturn(3, key, &keylen);
	CLIParserFree();
	
	if (keynlen != 2) {
		PrintAndLog("ERROR: <Key Num> must be 2 bytes long instead of: %d", keynlen);
		return 1;
	}
	
	if (keylen != 16) {
		PrintAndLog("ERROR: <Key Value> must be 16 bytes long instead of: %d", keylen);
		return 1;
	}

	UsbCommand c = {CMD_MIFARE_DESFIRE_AUTH1, {0x00, uid}};
	SendCommand(&c);

	UsbCommand resp;
	WaitForResponse(CMD_ACK,&resp);

	return 0;
}

static command_t CommandTable[] =
{
  {"help",             CmdHelp,					1, "This help"},
  {"auth",  	       CmdHFMFDesAuth,			0, "Authentication"},
  {NULL,               NULL,					0, NULL}
};

int CmdHFMFD(const char *Cmd) {
	(void)WaitForResponseTimeout(CMD_ACK,NULL,100);
	CmdsParse(CommandTable, Cmd);
	return 0;
}

int CmdHelp(const char *Cmd) {
  CmdsHelp(CommandTable);
  return 0;
}
