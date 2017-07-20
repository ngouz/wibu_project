#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include "CodeMeter.h"

void xDump(unsigned char *data, int l)
{
    int i;
    for(i = 0; i < l; i++)
    {
        printf("%02.2X", data[i]);
        if(i < l - 1)
            if((i & 15) != 15)
                printf(", ");
            else
                printf("\n");
        else
            printf("\n");
    }
}

void ErrorHandler(char *line, int ExitCode, HCMSysEntry hcmEntry)
{
    char acErrText[256];
    switch(CmGetLastErrorCode())
    {
        case CMERROR_NO_ERROR:
            return;
        case CMERROR_ENTRY_NOT_FOUND:
            fprintf(stderr, "%s: Appropriate entry not found.\n", line);
            break;
        case CMERROR_CRC_VERIFY_FAILED:
            fprintf(stderr, "%s: CRC validation failed.\n", line);
            break;
        case CMERROR_KEYSOURCEMISSED:
            fprintf(stderr, "%s: Key source is not available.\n", line);
            break;
        case CMERROR_KEYSOURCEWRONG:
            fprintf(stderr, "%s: The specified key is invalid (e.g. wrong length).\n", line);
            break;
        case CMERROR_INVALID_HANDLE:
            fprintf(stderr, "%s: Handle invalid! CmDongle removed?\n", line);
            break;
        default:
            CmGetLastErrorText(CM_GLET_ERRORTEXT, acErrText, sizeof(acErrText));
            fprintf(stderr, "%s: Other error occurred: \"%s\"\n", line, acErrText);
            break;
    }

    /* Despite the error try to close the handle. */
    if (NULL != hcmEntry)
      CmRelease(hcmEntry);
    exit(ExitCode);
}

int main(void)
{
    CMULONG ulFirmCode, ulProductCode, res, ulCRC;
    CMULONG cbData, ulExtType, ulType, ulFeatureCode;
    CMULONG flCtrl;
    int bEncrypt, bUseCRC;
    HCMSysEntry hcmEntry;
    CMCRYPT hcmCrypt;
    CMACCESS cmAcc;

   /* Set the data concerned. */
   /* Data is entered binary, Text is entered as 2-byte WideChar. */
    unsigned char abData[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};


   /* Set the variables identifying the CmDongle */
   /* and the action to be carried out. */
   /* Firm Code = Product Code = 0 will select the first found CmDongle. */

    ulFirmCode = 10;
    ulProductCode = 1;
    ulType = CM_CRYPT_SECRETDATA;
    ulExtType = 1;
    ulFeatureCode = 0;
    bEncrypt = 0;
    bUseCRC = 0;
    ulCRC = 0;
    cbData = sizeof(abData);

   /* The corresponding key source length has to be at least 16 bytes. */

   /* Access the CmDongle. */
    memset(&cmAcc, 0, sizeof(cmAcc));
    cmAcc.mflCtrl = CM_ACCESS_NOUSERLIMIT;
    cmAcc.mulFirmCode = ulFirmCode;
    cmAcc.mulProductCode = ulProductCode;
    cmAcc.mulFeatureCode = ulFeatureCode;

   /* Access the CmDongle only locally. */
    hcmEntry = CmAccess(CM_ACCESS_LOCAL , &cmAcc);

    if ( hcmEntry )
    {
      int nRet; //, k;
      unsigned int id = 0;
      CMBOXINFO aBoxInfo[4];
      nRet = CmGetBoxes(hcmEntry, CM_GB_ALLPORTS, &aBoxInfo[0], 4 );
      if (nRet > 0)
          id = aBoxInfo[0].mulSerialNumber;
    
    }

   /* Handle any errors. */
   /* Most probably no CmDongle with the appropriate Firm Code and Product Code was found. */
    ErrorHandler("CmAccess", 1, hcmEntry);
    if(NULL == hcmEntry){
      ErrorHandler("CmAccess", 1, hcmEntry);
    }

    memset(&hcmCrypt, 0, sizeof(hcmCrypt));
    hcmCrypt.mcmBaseCrypt.mflCtrl = ulType | CM_CRYPT_AES;

    if(bUseCRC)
    {
        if(bEncrypt)
            hcmCrypt.mcmBaseCrypt.mflCtrl |= CM_CRYPT_CALCCRC;
        else
            hcmCrypt.mcmBaseCrypt.mflCtrl |= CM_CRYPT_CHKCRC;
    }

    hcmCrypt.mcmBaseCrypt.mulKeyExtType = ulExtType;
    hcmCrypt.mcmBaseCrypt.mulFeatureCode = ulFeatureCode;
    hcmCrypt.mcmBaseCrypt.mulCrc = ulCRC;

    if(bEncrypt)
        flCtrl = CM_CRYPT_AES_ENC_CBC;
    else
        flCtrl = CM_CRYPT_AES_DEC_CBC;

    res = CmCrypt(hcmEntry, flCtrl, &hcmCrypt, abData, cbData);

    if(0 == res){
      ErrorHandler("CmCrypt", 2, hcmEntry);
    }

    printf("Encrypted/decrypted data:\n");
    xDump(abData, cbData);
    if(bEncrypt && bUseCRC)
        printf("Calculated CRC: %08.8X\n", hcmCrypt.mcmBaseCrypt.mulCrc);

   /* Clean up anything. */
    CmRelease(hcmEntry);
    return 0;
}
