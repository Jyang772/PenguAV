/*This program is free software: you can redistribute it and/or modify
it under the terms of the Lesser GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
Lesser GNU General Public License for more details.

You should have received a copy of the Lesser GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

Copyright 2013 MJaoune
*/

#include "gcvdb.h"
#include "md5/hashlibpp.h"
#include "VirusDatabase.h"

#include <QDebug>

Gcvdb::Gcvdb()
{
}

//Setup MD5 wrapper
hashwrapper *FileMD5Hash = new md5wrapper();

//Setup the ScanFile function to be called from external sources
//extern "C" __declspec(dllexport) const char* ScanFile(const char* file)

extern "C" const char* ScanFile(const char* file)
{
    qDebug() << "LAWLING";
    std::string filehash = FileMD5Hash->getHashFromFile(file);


    //Virus Database:





    //Microsoft Windows Virus Database
    Database::Virus TRADHGG;

    TRADHGG.md5 = "1532b48ab76ce545c28630adbd75e9fa";
    TRADHGG.name = "TR/ADH.GG";

    if (filehash == TRADHGG.md5)
    {
          return TRADHGG.name;
    }

    Database::Malware AdwareInstallCore573;

    AdwareInstallCore573.md5 = "42b1e5c3a0624350c34d2e856e902b75";
    AdwareInstallCore573.name = "Adware/InstallCore.5.73";

    if (filehash == AdwareInstallCore573.md5)
    {
        return AdwareInstallCore573.name;
    }


    Database::Malware AdwareInstallCore544;

    AdwareInstallCore544.md5 = "e539725dbca85b6e05a488946ef5c82e";
    AdwareInstallCore544.name = "Adware/InstallCore.5.44";

    if (filehash == AdwareInstallCore544.md5)
    {
        return AdwareInstallCore544.name;
    }

    Database::Malware AdwareInstallCore561;

    AdwareInstallCore561.md5 = "bda28958af3078ddc0a912ab51f40A07";
    AdwareInstallCore561.name = "Adware/InstallCore.5.61";

    if (filehash == AdwareInstallCore561.md5)
    {
        return AdwareInstallCore561.name;
    }

    Database::Malware AdwareInstallCore548;

    AdwareInstallCore548.md5 = "8b9817830039d7ec17df84a4aec82b49";
    AdwareInstallCore548.name = "Adware/InstallCore.5.48";

    if (filehash == AdwareInstallCore548.md5)
    {
        return AdwareInstallCore548.name;
    }

    Database::Malware AdwareInstallCore550;

    AdwareInstallCore550.md5 = "504ebcf1eb32502c164020a3bcc9abdb";
    AdwareInstallCore550.name = "Adware/InstallCore.5.50";

    if (filehash == AdwareInstallCore550.md5)
    {
        return AdwareInstallCore550.name;
    }

    Database::Malware AdwareSolimba1952;

    AdwareSolimba1952.md5 = "1868f5338b79f4722db89bc0ced46122";
    AdwareSolimba1952.name = "Adware/Solimba.1952";

    if (filehash == AdwareSolimba1952.md5)
    {
        return AdwareSolimba1952.name;
    }

    Database::Malware AdspyBhoGamePlBB;

    AdspyBhoGamePlBB.md5 = "99f0f439fa862ef1a2071fc113047b45";
    AdspyBhoGamePlBB.name = "Adspy/Bho.GamePl.BB";

    if (filehash == AdspyBhoGamePlBB.md5)
    {
        return AdspyBhoGamePlBB.name;
    }

    Database::Malware AdspyBhoGamePlaB;

    AdspyBhoGamePlaB.md5 = "f8b474e24a282b278c0E8ac39bb6c099";
    AdspyBhoGamePlaB.name = "Adspy/Bho.GamePla.B";

    if (filehash == AdspyBhoGamePlaB.md5)
    {
        return AdspyBhoGamePlaB.name;
    }

    Database::Malware AdwareInstCore350;

    AdwareInstCore350.md5 = "066b0A995cc74e0Deb916732a3550A69";
    AdwareInstCore350.name = "Adware/InstCore.350";

    if (filehash == AdwareInstCore350.md5)
    {
        return AdwareInstCore350.name;
    }

    Database::Malware AdwareInstallCore43;

    AdwareInstallCore43.md5 = "b3c71fca7997964bf8a6a66edb9c8b59";
    AdwareInstallCore43.name = "Adware/InstallCore.4.3";

    if (filehash == AdwareInstallCore43.md5)
    {
        return AdwareInstallCore43.name;
    }

    Database::Malware AdwareInstalCor199;

    AdwareInstalCor199.md5 = "8e80fc5ad2de1b27ba56b6d183425fd9";
    AdwareInstalCor199.name = "Adware/InstalCor.199";

    if (filehash == AdwareInstalCor199.md5)
    {
        return AdwareInstalCor199.name;
    }

    Database::Malware AdwareRelevantQ;

    AdwareRelevantQ.md5 = "Adware/Relevant.Q";
    AdwareRelevantQ.name = "cbd0707569ec6cf952912ac4c42c37da";

    if (filehash ==  AdwareRelevantQ.md5)
    {
        return  AdwareRelevantQ.name;
    }

    Database::Malware AdwareInstallCore143;

    AdwareInstallCore143.md5 = "3456518fd6fd89d582c1bc6f15c8e256";
    AdwareInstallCore143.name = "Adware/InstallCore.1.43";

    if (filehash ==  AdwareInstallCore143.md5)
    {
        return  AdwareInstallCore143.name;
    }

    Database::Malware AdwareInstallCore112;

    AdwareInstallCore112.md5 = "d420892051c4495b6923e2cd2849113a";
    AdwareInstallCore112.name = "Adware/InstallCore.1.12";

    if (filehash ==  AdwareInstallCore112.md5)
    {
        return  AdwareInstallCore112.name;
    }

    Database::Malware AdwareInstallCore12;

    AdwareInstallCore12.md5 = "2b5898a435edf320466ffa07ced76e3e";
    AdwareInstallCore12.name = "Adware/InstallCore.1.2";

    if (filehash ==  AdwareInstallCore12.md5)
    {
        return  AdwareInstallCore12.name;
    }

    Database::Malware AdwareAgentwxf3;

    AdwareAgentwxf3.md5 = "Adware/Agent.wxf.3";
    AdwareAgentwxf3.name = "bc8250539c7822421e2cd0e7c4dcb0b2";

    if (filehash ==  AdwareAgentwxf3.md5)
    {
        return  AdwareAgentwxf3.name;
    }

    Database::Malware ADSPYNaviPromoJ;

    ADSPYNaviPromoJ.md5 = "ADSPY/NaviPromo.J";
    ADSPYNaviPromoJ.name = "11033fe49e144984b82ae16ce1221cd0";

    if (filehash ==  ADSPYNaviPromoJ.md5)
    {
        return  ADSPYNaviPromoJ.name;
    }

    Database::Malware AdwareAgentNFM;

    AdwareAgentNFM.md5 = "a6a8ad9a95b8ea0cfe00c6f8ea78332f";
    AdwareAgentNFM.name = "Adware/Agent.NFM";

    if (filehash ==  AdwareAgentNFM.md5)
    {
        return  AdwareAgentNFM.name;
    }

    Database::Malware ADSPYZwangihw16;

    ADSPYZwangihw16.md5 = "3DBE1ABEA852AE2D0D22A9ADA3BA1CFA";
    ADSPYZwangihw16.name = "ADSPY/Zwangi.hw.16";

    if (filehash ==  ADSPYZwangihw16.md5)
    {
        return  ADSPYZwangihw16.name;
    }

    Database::Malware AdwareBoigy2248;

    AdwareBoigy2248.md5 = "0bf87f9a3b83ee3dbf9fe80c313f7056";
    AdwareBoigy2248.name = "Adware/Boigy.2.248";

    if (filehash ==  AdwareBoigy2248.md5)
    {
      return  AdwareBoigy2248.name;
    }

    Database::Malware AdwareSpigotAPE;

    AdwareSpigotAPE.md5 = "4464ef1a84ed7b1968a49efc410954a7";
    AdwareSpigotAPE.name = "Adware/Spigot.APE";

    if (filehash ==  AdwareSpigotAPE.md5)
    {
      return  AdwareSpigotAPE.name;
    }

    Database::Malware ADWAREGamePlayLabsA284;

    ADWAREGamePlayLabsA284.md5 = "2bc838df5ca1cc2931161e47377b03c6";
    ADWAREGamePlayLabsA284.name = "ADWARE/GamePlayLabs.A.284";

    if (filehash ==  ADWAREGamePlayLabsA284.md5)
    {
      return  ADWAREGamePlayLabsA284.name;
    }

    Database::Malware ADWAREAgentGabaecb;

    ADWAREAgentGabaecb.md5 = "EA92F34BDDA3BFABEFDD8B19D883DB09";
    ADWAREAgentGabaecb.name = "ADWARE/Agent.Gabaecb";

    if (filehash ==  ADWAREAgentGabaecb.md5)
    {
      return  ADWAREAgentGabaecb.name;
    }

    Database::Malware ADWAREAgentTangoc;

    ADWAREAgentTangoc.md5 = "7a84469d4e9f204c4958e1d0a84c8d94";
    ADWAREAgentTangoc.name = "ADWARE/Agent.Tango.c";

    if (filehash ==  ADWAREAgentTangoc.md5)
    {
      return  ADWAREAgentTangoc.name;
    }

    Database::Malware ADWAREBandooAA;

    ADWAREBandooAA.md5 = "2061d7fabb8729c210bdc428ddbbabc0";
    ADWAREBandooAA.name = "ADWARE/Bandoo.AA";

    if (filehash ==  ADWAREBandooAA.md5)
    {
      return  ADWAREBandooAA.name;
    }

    Database::Malware ADWAREZwangiahb;

    ADWAREZwangiahb.md5 = "0088f4ecdc99ae934be22499e7d75968";
    ADWAREZwangiahb.name = "ADWARE/Zwangi.ahb";

    if (filehash ==  ADWAREZwangiahb.md5)
    {
      return  ADWAREZwangiahb.name;
    }

    Database::Malware ADSPYSmartShoper;

    ADSPYSmartShoper.md5 = "f937c3907123ac59d333fbdc799fb5cf";
    ADSPYSmartShoper.name = "ADSPY/SmartShoper";

    if (filehash ==  ADSPYSmartShoper.md5)
    {
      return  ADSPYSmartShoper.name;
    }

    Database::Malware APPLModiFFA;

    APPLModiFFA.md5 = "8f2f7912194119b5d1e48d570b53a56b";
    APPLModiFFA.name = "APPL/ModiFF.A";

    if (filehash ==  APPLModiFFA.md5)
    {
      return  APPLModiFFA.name;
    }

    Database::Malware ADSPYHobaA;

    ADSPYHobaA.md5 = "c58088d4c0cea2c191fed21b1ca2383c";
    ADSPYHobaA.name = "ADSPY/Hoba.A";

    if (filehash ==  ADSPYHobaA.md5)
    {
      return  ADSPYHobaA.name;
    }

    Database::Malware ADSPYGibmedA4;

    ADSPYGibmedA4.md5 = "97668ab47a2308cc5e9b4c99e20715bb";
    ADSPYGibmedA4.name = "ADSPY/Gibmed.A.4";

    if (filehash ==  ADSPYGibmedA4.md5)
    {
      return  ADSPYGibmedA4.name;
    }

    Database::Malware ADSPYGibmedB3;

    ADSPYGibmedB3.md5 = "b6029e8a17264e5cf71d3be7997be2a1";
    ADSPYGibmedB3.name = "ADSPY/Gibmed.B.3";

    if (filehash ==  ADSPYGibmedB3.md5)
    {
      return  ADSPYGibmedB3.name;
    }

    Database::Malware APPLNirCmdA;

    APPLNirCmdA.md5 = "4910aa5bd2caabb06dd80529ff18f9a0";
    APPLNirCmdA.name = "APPL/NirCmd.A";

    if (filehash ==  APPLNirCmdA.md5)
    {
      return  APPLNirCmdA.name;
    }

    Database::Malware APPLHideDirA;

    APPLHideDirA.md5 = "4def017b8d6a6a33c000e3252924c45a";
    APPLHideDirA.name = "APPL/HideDir.A";

    if (filehash ==  APPLHideDirA.md5)
    {
      return  APPLHideDirA.name;
    }

    Database::Malware APPLKillAppA;

    APPLKillAppA.md5 = "fb9f5efc10280F3659dce48069725c3c";
    APPLKillAppA.name = "APPL/KillApp.A";

    if (filehash ==  APPLKillAppA.md5)
    {
      return  APPLKillAppA.name;
    }

    Database::Malware ADSPYAgentAP7;

    ADSPYAgentAP7.md5 = "fc2936e5c2c1bcfcaaf40c8a7f2f69b9";
    ADSPYAgentAP7.name = "ADSPY/Agent.AP.7";

    if (filehash ==  ADSPYAgentAP7.md5)
    {
      return  ADSPYAgentAP7.name;
    }

    Database::Malware ADSPYBoranX19C;

    ADSPYBoranX19C.md5 = "a7a755674ff94672153fd54d7ceaf823";
    ADSPYBoranX19C.name = "ADSPY/Boran.X.19.C";

    if (filehash ==  ADSPYBoranX19C.md5)
    {
      return  ADSPYBoranX19C.name;
    }

    Database::Malware ADSPYWiADAF1;

    ADSPYWiADAF1.md5 = "29f3b3d328c14360d96e4a2c24790a79";
    ADSPYWiADAF1.name = "ADSPY/WiAD.AF.1";

    if (filehash ==  ADSPYWiADAF1.md5)
    {
      return  ADSPYWiADAF1.name;
    }

    Database::Malware ADSPYWinADAF1;

    ADSPYWinADAF1.md5 = "7c282c5a5c5491f753284a614f57c375";
    ADSPYWinADAF1.name = "ADSPY/WinAD.AF.1";

    if (filehash ==  ADSPYWinADAF1.md5)
    {
      return  ADSPYWinADAF1.name;
    }

    Database::Malware ADSPYWinADAT3;

    ADSPYWinADAT3.md5 = "f82a79f7c5b226a53864a3fe6406d9e5";
    ADSPYWinADAT3.name = "ADSPY/WinAD.AT.3";

    if (filehash ==  ADSPYWinADAT3.md5)
    {
      return  ADSPYWinADAT3.name;
    }

    Database::Malware ADSPYAlerterA;

    ADSPYAlerterA.md5 = "94271d3e09d9058b14ab5edc40d56035";
    ADSPYAlerterA.name = "ADSPY/Alerter.A";

    if (filehash ==  ADSPYAlerterA.md5)
    {
      return  ADSPYAlerterA.name;
    }

    Database::Malware ADSPYBoranI18;

    ADSPYBoranI18.md5 = "4aa01d99ea02fd25cc8076f33a1cd49c";
    ADSPYBoranI18.name = "ADSPY/Boran.I.18";

    if (filehash ==  ADSPYBoranI18.md5)
    {
      return  ADSPYBoranI18.name;
    }

    Database::Malware ADSPYBaiduBarP;

    ADSPYBaiduBarP.md5 = "306cee9a4db1909c45960c79980413fd";
    ADSPYBaiduBarP.name = "ADSPY/BaiduBar.P";

    if (filehash ==  ADSPYBaiduBarP.md5)
    {
      return  ADSPYBaiduBarP.name;
    }

    Database::Malware ADSPYBoranO2;

    ADSPYBoranO2.md5 = "1f4b04a85768205ae5452415dc843e3d";
    ADSPYBoranO2.name = "ADSPY/Boran.O.2";

    if (filehash ==  ADSPYBoranO2.md5)
    {
      return  ADSPYBoranO2.name;
    }

    Database::Malware ADSPYBoranO1;

    ADSPYBoranO1.md5 = "3c6f191fe0a913c40E7139d66ba0f7ac";
    ADSPYBoranO1.name = "ADSPY/Boran.O.1";

    if (filehash ==  ADSPYBoranO1.md5)
    {
      return  ADSPYBoranO1.name;
    }

    Database::Malware ADSPYIEHlprF2;

    ADSPYIEHlprF2.md5 = "4242246b3403cfc7809fd4604967953d";
    ADSPYIEHlprF2.name = "ADSPY/IEHlpr.F.2";

    if (filehash ==  ADSPYIEHlprF2.md5)
    {
      return  ADSPYIEHlprF2.name;
    }

    Database::Malware ADSPYBoranI17;

    ADSPYBoranI17.md5 = "29987dbd0Ec36ff87cd572f0d75c2c5a";
    ADSPYBoranI17.name = "ADSPY/Boran.I.17";

    if (filehash ==  ADSPYBoranI17.md5)
    {
      return  ADSPYBoranI17.name;
    }

    Database::Malware ADSPYVirtumondeB;

    ADSPYVirtumondeB.md5 = "5b00c4a26bfb132b7c5b8692949d227b";
    ADSPYVirtumondeB.name = "ADSPY/Virtumonde.B";

    if (filehash ==  ADSPYVirtumondeB.md5)
    {
      return  ADSPYVirtumondeB.name;
    }

    Database::Malware ADSPYSpySheriffB;

    ADSPYSpySheriffB.md5 = "50db7750d6a2afa721cbccf4c210fe48";
    ADSPYSpySheriffB.name = "ADSPY/SpySheriff.B";

    if (filehash ==  ADSPYSpySheriffB.md5)
    {
      return  ADSPYSpySheriffB.name;
    }

    Database::Malware ADSPYSpySheriffHP;

    ADSPYSpySheriffHP.md5 = "2aaebbbc549d14993694182ca5aaed34";
    ADSPYSpySheriffHP.name = "ADSPY/SpySheriff.HP";

    if (filehash ==  ADSPYSpySheriffHP.md5)
    {
      return  ADSPYSpySheriffHP.name;
    }

    Database::Malware ADSPYClickSpri1B;

    ADSPYClickSpri1B.md5 = "5afb9b6f1acd7dc9d4b87cb16f16a704";
    ADSPYClickSpri1B.name = "ADSPY/ClickSpri.1.B";

    if (filehash ==  ADSPYClickSpri1B.md5)
    {
      return  ADSPYClickSpri1B.name;
    }

    Database::Malware ADSPYISearchd2;

    ADSPYISearchd2.md5 = "f822ce94e5bfa827143a8457c70F9210";
    ADSPYISearchd2.name = "ADSPY/ISearch.d.2";

    if (filehash ==  ADSPYISearchd2.md5)
    {
      return  ADSPYISearchd2.name;
    }

    Database::Malware ADSPYCashDeluxeG;

    ADSPYCashDeluxeG.md5 = "4a034bbe3992239ddca34b67e6d3f3c4";
    ADSPYCashDeluxeG.name = "ADSPY/CashDeluxe.G";

    if (filehash ==  ADSPYCashDeluxeG.md5)
    {
      return  ADSPYCashDeluxeG.name;
    }

    Database::Malware ADSPYLook2MeAB67;

    ADSPYLook2MeAB67.md5 = "242a20bae9cf9cb816a447150378c02d";
    ADSPYLook2MeAB67.name = "ADSPY/Look2Me.AB.67";

    if (filehash ==  ADSPYLook2MeAB67.md5)
    {
      return  ADSPYLook2MeAB67.name;
    }

    Database::Malware ADSPYHoaxRenosAG;

    ADSPYHoaxRenosAG.md5 = "a5a84ed083f9cb0A46369c044eecab73";
    ADSPYHoaxRenosAG.name = "ADSPY/Hoax.Renos.AG";

    if (filehash ==  ADSPYHoaxRenosAG.md5)
    {
      return  ADSPYHoaxRenosAG.name;
    }

    Database::Malware ADSPYMsnagentB;

    ADSPYMsnagentB.md5 = "4ced774c3902ccaa41bb30a165f68e31";
    ADSPYMsnagentB.name = "ADSPY/Msnagent.B";

    if (filehash ==  ADSPYMsnagentB.md5)
    {
      return  ADSPYMsnagentB.name;
    }

    Database::Malware ADSPYPremiumSear2;

    ADSPYPremiumSear2.md5 = "F21056EA283B0AD0424449D770D2CE97";
    ADSPYPremiumSear2.name = "ADSPY/PremiumSear.2";

    if (filehash ==  ADSPYPremiumSear2.md5)
    {
      return  ADSPYPremiumSear2.name;
    }

    Database::Malware ADSPYToolBarZbarH4;

    ADSPYToolBarZbarH4.md5 = "756cb08d3df29b1c17ed6706b4c0103b";
    ADSPYToolBarZbarH4.name = "ADSPY/ToolBar.Zbar.H.4";

    if (filehash ==  ADSPYToolBarZbarH4.md5)
    {
      return  ADSPYToolBarZbarH4.name;
    }

    Database::Malware ADSPYMediaticketsE;

    ADSPYMediaticketsE.md5 = "02cd0535a0c1f4c5bbd5864bdb62991f";
    ADSPYMediaticketsE.name = "ADSPY/Mediatickets.E";

    if (filehash ==  ADSPYMediaticketsE.md5)
    {
      return  ADSPYMediaticketsE.name;
    }

    Database::Malware ADSPYWinAD;

    ADSPYWinAD.md5 = "7daf5088982008bca681a5ede35860ab";
    ADSPYWinAD.name = "ADSPY/WinAD";

    if (filehash ==  ADSPYWinAD.md5)
    {
      return  ADSPYWinAD.name;
    }

    Database::Malware ADSPYBarElitAP4;

    ADSPYBarElitAP4.md5 = "E3D04B301860BCDA505D616D1D2FE453";
    ADSPYBarElitAP4.name = "ADSPY/Bar.Elit.AP.4";

    if (filehash ==  ADSPYBarElitAP4.md5)
    {
      return  ADSPYBarElitAP4.name;
    }

    Database::Virus BATKillExploreES;

    BATKillExploreES.md5 = "1277b2e3a1771d53d7e83777008ee705";
    BATKillExploreES.name = "BAT/KillExplore.ES";

    if (filehash ==  BATKillExploreES.md5)
    {
      return  BATKillExploreES.name;
    }

    Database::Malware BOOTDssM;

    BOOTDssM.md5 = "e150aa222b36a35132cc917c79ed87d1";
    BOOTDssM.name = "BOO/TDss.M";

    if (filehash ==  BOOTDssM.md5)
    {
      return  BOOTDssM.name;
    }

    Database::Malware BOOTDssA;

    BOOTDssA.md5 = "317d3910dd859c49feeb3ab9c6594fd6";
    BOOTDssA.name = "BOO/TDss.A";

    if (filehash ==  BOOTDssA.md5)
    {
      return  BOOTDssA.name;
    }

    Database::Virus BATAgent140;

    BATAgent140.md5 = "317d3910dd859c49feeb3ab9c6594fd6";
    BATAgent140.name = "BAT/Agent.140";

    if (filehash ==  BATAgent140.md5)
    {
      return  BATAgent140.name;
    }

    Database::Malware CC00233;

    CC00233.md5 = "6009bea4c310ed64cf37b1eed3c0cf7e";
    CC00233.name = "CC/00233";

    if (filehash ==  CC00233.md5)
    {
      return  CC00233.name;
    }

    Database::Malware DRSettyO;

    DRSettyO.md5 = "459dedf5135d8d6eff5a08d62f328f5d";
    DRSettyO.name = "DR/Setty.O";

    if (filehash ==  DRSettyO.md5)
    {
      return  DRSettyO.name;
    }

    Database::Malware DRAutoitYH240;

    DRAutoitYH240.md5 = "f8bfb7e4337651e5c002602cca0fe6ad";
    DRAutoitYH240.name = "DR/Autoit.YH.240";

    if (filehash ==  DRAutoitYH240.md5)
    {
      return  DRAutoitYH240.name;
    }

    Database::Malware DRAutoitYH59;

    DRAutoitYH59.md5 = "3bb7ee908bd9adaf7449f02d71d60306";
    DRAutoitYH59.name = "DR/Autoit.YH.59";

    if (filehash ==  DRAutoitYH59.md5)
    {
      return  DRAutoitYH59.name;
    }

    Database::Malware DRAutoitYH331;

    DRAutoitYH331.md5 = "8c78dc19db83e8ad55eb4a8732476d57";
    DRAutoitYH331.name = "DR/Autoit.YH.331";

    if (filehash ==  DRAutoitYH331.md5)
    {
      return  DRAutoitYH331.name;
    }

    Database::Malware DRAutoitaft598;

    DRAutoitaft598.md5 = "80b5a47e61b73e49b1e586a501762ac2";
    DRAutoitaft598.name = "DR/Autoit.aft.598";

    if (filehash ==  DRAutoitaft598.md5)
    {
      return  DRAutoitaft598.name;
    }

    Database::Malware DRAutoitaft185;

    DRAutoitaft185.md5 = "c6342635d5763c5d90778e8fe4062de1";
    DRAutoitaft185.name = "DR/Autoit.aft.185";

    if (filehash ==  DRAutoitaft185.md5)
    {
      return  DRAutoitaft185.name;
    }

    Database::Malware DRAutoitYH179;

    DRAutoitYH179.md5 = "04307bfa1ae3d14bbe2433355d77cd91";
    DRAutoitYH179.name = "DR/Autoit.YH.179";

    if (filehash ==  DRAutoitYH179.md5)
    {
      return  DRAutoitYH179.name;
    }

    Database::Malware DRAutoitWX25;

    DRAutoitWX25.md5 = "a32e6493cb613ed9a41031f9f8b72830";
    DRAutoitWX25.name = "DR/Autoit.WX.25";

    if (filehash ==  DRAutoitWX25.md5)
    {
      return  DRAutoitWX25.name;
    }


    Database::Malware DRAutoitacz;

    DRAutoitacz.md5 = "3c3cd5ae789f4b9ebc0c307c7123a5bd";
    DRAutoitacz.name = "DR/Autoit.acz";

    if (filehash ==  DRAutoitacz.md5)
    {
      return  DRAutoitacz.name;
    }

    Database::Malware DRAutoitRU6;

    DRAutoitRU6.md5 = "1dbefef6c17f82a4a4c90d7ea9476a6f";
    DRAutoitRU6.name = "DR/Autoit.RU.6";

    if (filehash ==  DRAutoitRU6.md5)
    {
      return  DRAutoitRU6.name;
    }

    Database::Malware DRAutoitBN;

    DRAutoitBN.md5 = "b7a7e7c7f6ba1f89fbdda06e0701ae7c";
    DRAutoitBN.name = "DR/Autoit.BN";

    if (filehash ==  DRAutoitBN.md5)
    {
      return  DRAutoitBN.name;
    }

    Database::Malware DRAutoitX28;

    DRAutoitX28.md5 = "f88648076d23fb08c04b5c1ec94f3965";
    DRAutoitX28.name = "DR/Autoit.X.28";

    if (filehash ==  DRAutoitX28.md5)
    {
      return  DRAutoitX28.name;
    }

    Database::Malware DRSohanadBM157;

    DRSohanadBM157.md5 = "ec80ba08fe2710d8ab5ad280f1b37137";
    DRSohanadBM157.name = "DR/Sohanad.BM.157";

    if (filehash ==  DRSohanadBM157.md5)
    {
      return  DRSohanadBM157.name;
    }

    Database::Malware DRAutoitRL;

    DRAutoitRL.md5 = "e26110b93d3e2b047f11cb9b3158cc35";
    DRAutoitRL.name = "DR/Autoit.RL";

    if (filehash ==  DRAutoitRL.md5)
    {
      return  DRAutoitRL.name;
    }

    Database::Malware DRAutoitI2;

    DRAutoitI2.md5 = "3b5cf70876ef2e58a30dfa85c16b49bd";
    DRAutoitI2.name = "DR/Autoit.I.2";

    if (filehash ==  DRAutoitI2.md5)
    {
      return  DRAutoitI2.name;
    }

    Database::Malware DRStartPageAD;

    DRStartPageAD.md5 = "aa5c8f637696e68b9b8b82a2c3491155";
    DRStartPageAD.name = "DR/StartPage.AD";

    if (filehash ==  DRStartPageAD.md5)
    {
      return  DRStartPageAD.name;
    }

    Database::Malware DRAgent24576D;

    DRAgent24576D.md5 = "816852a7b5f831e6f2c517e4adab4c8b";
    DRAgent24576D.name = "DR/Agent.24576.D";

    if (filehash ==  DRAgent24576D.md5)
    {
      return  DRAgent24576D.name;
    }

    Database::Malware DRAutoitXH;

    DRAutoitXH.md5 = "862b8fa9bd546e06dac3f0ba8ae86647";
    DRAutoitXH.name = "DR.Autoit.XH";

    if (filehash ==  DRAutoitXH.md5)
    {
      return  DRAutoitXH.name;
    }

    Database::Malware DRDldrAgentasyh1;

    DRDldrAgentasyh1.md5 = "75ef772716d920456bab8af3b5dc7a4b";
    DRDldrAgentasyh1.name = "DR/Dldr.Agent.asyh.1";

    if (filehash ==  DRDldrAgentasyh1.md5)
    {
      return  DRDldrAgentasyh1.name;
    }

    Database::Malware DRDldrVBVYP;

    DRDldrVBVYP.md5 = "4458edeed674cd4665a10Cdeebbc1004";
    DRDldrVBVYP.name = "DR/Dldr.VB.VYP";

    if (filehash ==  DRDldrVBVYP.md5)
    {
      return  DRDldrVBVYP.name;
    }

    Database::Malware DRCinmusdtk;

    DRCinmusdtk.md5 = "a67931fcd5c27b9d94a7b05be2003c6f";
    DRCinmusdtk.name = "DR/Cinmus.dtk";

    if (filehash ==  DRCinmusdtk.md5)
    {
      return  DRCinmusdtk.name;
    }

    Database::Malware DRAutoRunlte;

    DRAutoRunlte.md5 = "9d1e98012ca53a4604db01b5d8e5ada4";
    DRAutoRunlte.name = "DR/AutoRun.lte";

    if (filehash ==  DRAutoRunlte.md5)
    {
      return  DRAutoRunlte.name;
    }

    Database::Malware DRZlobiwm;

    DRZlobiwm.md5 = "310155bd61cf7370031799b366333bba";
    DRZlobiwm.name = "DR/Zlob.iwm";

    if (filehash ==  DRZlobiwm.md5)
    {
      return  DRZlobiwm.name;
    }

    Database::Malware DRAgentabpc;

    DRAgentabpc.md5 = "fbfa83375dc26b6f4bdbbb6f6f73ef56";
    DRAgentabpc.name = "DR/Agent.abpc";

    if (filehash ==  DRAgentabpc.md5)
    {
      return  DRAgentabpc.name;
    }

    Database::Malware DRCinmusRI;

    DRCinmusRI.md5 = "d00611765b55111a0f8aea92469c603c";
    DRCinmusRI.name = "DR/Cinmus.RI";

    if (filehash ==  DRCinmusRI.md5)
    {
      return  DRCinmusRI.name;
    }

    Database::Malware DRGator320214;

    DRGator320214.md5 = "dc9c9a3d61ebb3a9feb49b3e04356e4b";
    DRGator320214.name = "DR/Gator.3202.14";

    if (filehash ==  DRGator320214.md5)
    {
      return  DRGator320214.name;
    }

    Database::Malware DRAgentqvu;

    DRAgentqvu.md5 = "62dc481fb9f9baf8b31cbbeeaa80ad2c";
    DRAgentqvu.name = "DR/Agent.qvu";

    if (filehash ==  DRAgentqvu.md5)
    {
      return  DRAgentqvu.name;
    }

    Database::Malware DRBuzusqvy;

    DRBuzusqvy.md5 = "36afa252a0390dca2f3aeea419349a0d";
    DRBuzusqvy.name = "DR/Buzus.qvy";

    if (filehash ==  DRBuzusqvy.md5)
    {
      return  DRBuzusqvy.name;
    }

    Database::Malware DRMirarAJ;

    DRMirarAJ.md5 = "805d4838a288836279bdeecb30d00ed9";
    DRMirarAJ.name = "DR/Mirar.AJ";

    if (filehash ==  DRMirarAJ.md5)
    {
      return  DRMirarAJ.name;
    }

    Database::Malware DRAgentrgc;

    DRAgentrgc.md5 = "a95dd571ea3c3aff30245cf9cae46d50";
    DRAgentrgc.name = "DR/Agent.rgc";

    if (filehash ==  DRAgentrgc.md5)
    {
      return  DRAgentrgc.name;
    }

    Database::Malware DRAgentabpb1;

    DRAgentabpb1.md5 = "0cf60f6b9a43cf621f540d26128cdfab";
    DRAgentabpb1.name = "DR/Agent.abpb.1";

    if (filehash ==  DRAgentabpb1.md5)
    {
      return  DRAgentabpb1.name;
    }

    Database::Malware DRAutoitI1;

    DRAutoitI1.md5 = "69718103c21fd0e647d47c364758f215";
    DRAutoitI1.name = "DR/Autoit.I.1";

    if (filehash ==  DRAutoitI1.md5)
    {
      return  DRAutoitI1.name;
    }

    Database::Malware DRZapchastAI;

    DRZapchastAI.md5 = "7824396444ea3c178cc677b6de9f49c8";
    DRZapchastAI.name = "DR/Zapchast.AI";

    if (filehash == DRZapchastAI.md5)
    {
      return  DRZapchastAI.name;
    }

    Database::Malware DRCinmusdol;

    DRCinmusdol.md5 = "c5d61213ae4e6ab03df1307ddd348b5b";
    DRCinmusdol.name = "DR/Cinmus.dol";

    if (filehash == DRCinmusdol.md5)
    {
      return  DRCinmusdol.name;
    }

    Database::Malware DRMonder320653;

    DRMonder320653.md5 = "761f7caed9d18ec4569ac99bff2e2ac3";
    DRMonder320653.name = "DR/Monder.320653";

    if (filehash == DRMonder320653.md5)
    {
      return  DRMonder320653.name;
    }

    Database::Malware DRShopperV14;

    DRShopperV14.md5 = "840c52c0e30872ee5af9fe29bd04f883";
    DRShopperV14.name = "DR/Shopper.V.14";

    if (filehash == DRShopperV14.md5)
    {
      return  DRShopperV14.name;
    }

    Database::Malware DROneStepC137;

    DROneStepC137.md5 = "a920af7bc6b6b8824c52a6b6ae533321";
    DROneStepC137.name = "DR/OneStep.C.137";

    if (filehash == DROneStepC137.md5)
    {
      return  DROneStepC137.name;
    }

    Database::Malware DRDelfHME;

    DRDelfHME.md5 = "e498562415e5a4869c8c2fd698c404fd";
    DRDelfHME.name = "DR/Delf.HME";

    if (filehash == DRDelfHME.md5)
    {
      return  DRDelfHME.name;
    }

    Database::Malware DRMyWebSearchAU;

    DRMyWebSearchAU.md5 = "45a84b7590b49b5828d608fa06dff781";
    DRMyWebSearchAU.name = "DR/MyWebSearch.AU";

    if (filehash == DRMyWebSearchAU.md5)
    {
      return  DRMyWebSearchAU.name;
    }

    Database::Malware DRPSWVBJI;

    DRPSWVBJI.md5 = "a51e4cf019c203f7b5d56e673bb751e4";
    DRPSWVBJI.name = "DR/PSW.VB.JI";

    if (filehash == DRPSWVBJI.md5)
    {
      return  DRPSWVBJI.name;
    }

    Database::Malware DRSohanadT2;

    DRSohanadT2.md5 = "790Ddc293c8f45ec337292cb57a3ee41";
    DRSohanadT2.name = "DR/Sohanad.T.2";

    if (filehash == DRSohanadT2.md5)
    {
      return  DRSohanadT2.name;
    }

    Database::Malware DRMartShop2;

    DRMartShop2.md5 = "227e5c2e07281eff8d13705498b19792";
    DRMartShop2.name = "DR/MartShop.2";

    if (filehash == DRMartShop2.md5)
    {
      return  DRMartShop2.name;
    }

    Database::Malware DRDldrDelfble1;

    DRDldrDelfble1.md5 = "00f86cc9119df98fb71f36b6715420ea";
    DRDldrDelfble1.name = "DR/Dldr.Delf.ble.1";

    if (filehash == DRDldrDelfble1.md5)
    {
      return  DRDldrDelfble1.name;
    }

    Database::Malware DRDldrDelfble;

    DRDldrDelfble.md5 = "0B7014677a5e1422646ae8e9a31ffbef";
    DRDldrDelfble.name = "DR/Dldr.Delf.ble";

    if (filehash == DRDldrDelfble.md5)
    {
      return  DRDldrDelfble.name;
    }

    Database::Malware DRZlob6378845;

    DRZlob6378845.md5 = "8bc2cec2527e2a95e123184008142c63";
    DRZlob6378845.name = "DR/Zlob.63788.45";

    if (filehash == DRZlob6378845.md5)
    {
      return  DRZlob6378845.name;
    }

    Database::Malware DRDldrAdloadCA;

    DRDldrAdloadCA.md5 = "ea66541590cea422c8163977e509454b";
    DRDldrAdloadCA.name = "DR/Dldr.Adload.CA";

    if (filehash == DRDldrAdloadCA.md5)
    {
      return  DRDldrAdloadCA.name;
    }

    Database::Malware DRPortlessK1;

    DRPortlessK1.md5 = "89c414f68d50b9a146d1e0761fc05bc9";
    DRPortlessK1.name = "DR/Portless.K.1";

    if (filehash == DRPortlessK1.md5)
    {
      return  DRPortlessK1.name;
    }

    Database::Malware DRDropperSmallQD;

    DRDropperSmallQD.md5 = "5b7dc5a149720Fc5a4fdf2ffb6f91c7e";
    DRDropperSmallQD.name = "DR/Dropper.Small.QD";

    if (filehash == DRDropperSmallQD.md5)
    {
      return  DRDropperSmallQD.name;
    }

    Database::Malware DRDldrSmallajc1;

    DRDldrSmallajc1.md5 = "82ebda32bc55fba6e2e10A7cb5a7ad31";
    DRDldrSmallajc1.name = "DR/Dldr.Small.ajc.1";

    if (filehash == DRDldrSmallajc1.md5)
    {
      return  DRDldrSmallajc1.name;
    }

    Database::Malware DRXbotL;

    DRXbotL.md5 = "2188b1bc1342c0824c2f5429678a310C";
    DRXbotL.name = "DR/Xbot.L";

    if (filehash == DRXbotL.md5)
    {
      return  DRXbotL.name;
    }

    Database::Malware DRSoftomateQ1;

    DRSoftomateQ1.md5 = "0E3f20d50B80021303dfb19bd8214ff2";
    DRSoftomateQ1.name = "DR/Softomate.Q.1";

    if (filehash == DRSoftomateQ1.md5)
    {
      return  DRSoftomateQ1.name;
    }

    Database::Malware DRCometC;

    DRCometC.md5 = "5d4bafc55c27545a1121ffad220408f3";
    DRCometC.name = "DR/Comet.C";

    if (filehash == DRCometC.md5)
    {
      return  DRCometC.name;
    }

    Database::Malware DRDldrSmallctp;

    DRDldrSmallctp.md5 = "66b008d918e68e174d96a35f6a6baa7e";
    DRDldrSmallctp.name = "DR/Dldr.Small.ctp";

    if (filehash == DRDldrSmallctp.md5)
    {
      return  DRDldrSmallctp.name;
    }

    Database::Malware DRMahayouA;

    DRMahayouA.md5 = "c05c5f92e4a86c99c6996de040a31b6d";
    DRMahayouA.name = "DR/Mahayou.A";

    if (filehash == DRMahayouA.md5)
    {
      return  DRMahayouA.name;
    }

    Database::Malware DRDldrNSISAgentP;

    DRDldrNSISAgentP.md5 = "a1a6795997b094bcbb3a5655ebb9ee8d";
    DRDldrNSISAgentP.name = "DR/Dldr.NSIS.Agent.P";

    if (filehash == DRDldrNSISAgentP.md5)
    {
      return  DRDldrNSISAgentP.name;
    }

    Database::Malware DRSoberW;

    DRSoberW.md5 = "2db904c82154edb22b2e23603930061a";
    DRSoberW.name = "DR/Sober.W";

    if (filehash == DRSoberW.md5)
    {
      return  DRSoberW.name;
    }

    Database::Malware DRSoberX;

    DRSoberX.md5 = "eb561e6b4669bdf44292a449fa418ab2";
    DRSoberX.name = "DR/Sober.X";

    if (filehash == DRSoberX.md5)
    {
      return  DRSoberX.name;
    }

    Database::Malware DRSpyWebRecordeB;

    DRSpyWebRecordeB.md5 = "215be9f0cad633e4495e0ce618663ca5";
    DRSpyWebRecordeB.name = "DR/Spy.WebRecorde.B";

    if (filehash == DRSpyWebRecordeB.md5)
    {
      return  DRSpyWebRecordeB.name;
    }

    Database::Malware DRSdBot115487;

    DRSdBot115487.md5 = "512bdab878e14db7bb83afd5b2193de8";
    DRSdBot115487.name = "DR/SdBot.115487";

    if (filehash == DRSdBot115487.md5)
    {
      return  DRSdBot115487.name;
    }

    Database::Malware DRMicrojoinJ;

    DRMicrojoinJ.md5 = "55B8C0F3A89562DA92A76B1B43CC1128";
    DRMicrojoinJ.name = "DR/Microjoin.J";

    if (filehash == DRMicrojoinJ.md5)
    {
      return  DRMicrojoinJ.name;
    }

    Database::Malware DRGoldunCI;

    DRGoldunCI.md5 = "E24B4A52B7DF30EFF2E9C256FF138148";
    DRGoldunCI.name = "DR/Goldun.CI";

    if (filehash == DRGoldunCI.md5)
    {
      return  DRGoldunCI.name;
    }

    Database::Malware DRMytobKI;

    DRMytobKI.md5 = "dfe60d08202235cbfe7ff257010236c9";
    DRMytobKI.name = "DR/Mytob.KI";

    if (filehash == DRMytobKI.md5)
    {
      return  DRMytobKI.name;
    }

    Database::Malware DRBagleP;

    DRBagleP.md5 = "4fb426de872ee9b20c3312fae3adf018";
    DRBagleP.name = "DR/Bagle.P";

    if (filehash == DRBagleP.md5)
    {
      return  DRBagleP.name;
    }

    Database::Malware DRBagleO2;

    DRBagleO2.md5 = "1af3a1c3261aab9b61b17e1d94c504db";
    DRBagleO2.name = "DR/Bagle.O.2";

    if (filehash == DRBagleO2.md5)
    {
      return  DRBagleO2.name;
    }

    Database::Malware DRBagleO;

    DRBagleO.md5 = "a417576619e9c049e988d1f335544d48";
    DRBagleO.name = "DR/Bagle.O";

    if (filehash == DRBagleO.md5)
    {
      return  DRBagleO.name;
    }

    Database::Malware DRAgentMT;

    DRAgentMT.md5 = "af9b414ca4e341e76d07e999aa1e0faa";
    DRAgentMT.name = "DR/Agent.MT";

    if (filehash == DRAgentMT.md5)
    {
      return  DRAgentMT.name;
    }

    Database::Malware DRIRCFlooder3;

    DRIRCFlooder3.md5 = "6e0719a82b08b04a39d5c4169bec6b0e";
    DRIRCFlooder3.name = "DR/IRCFlooder.3";

    if (filehash == DRIRCFlooder3.md5)
    {
      return  DRIRCFlooder3.name;
    }

    Database::Malware DRProxyRankyZ18;

    DRProxyRankyZ18.md5 = "497407b1c0b44ff52a1390c87197ebb6";
    DRProxyRankyZ18.name = "DR/Proxy.Ranky.Z.18";

    if (filehash == DRProxyRankyZ18.md5)
    {
      return  DRProxyRankyZ18.name;
    }

    Database::Malware DRIRCBot8184B;

    DRIRCBot8184B.md5 = "84f9161a7580ca8ae571c41230eaa77d";
    DRIRCBot8184B.name = "DR/IRCBot.8184.B";

    if (filehash == DRIRCBot8184B.md5)
    {
      return  DRIRCBot8184B.name;
    }

    Database::Malware DRSdBotacq;

    DRSdBotacq.md5 = "63f1a3a4be54a67d75b4b9457af7c865";
    DRSdBotacq.name = "DR/SdBot.acq";

    if (filehash == DRSdBotacq.md5)
    {
      return  DRSdBotacq.name;
    }

    Database::Malware EicarTestSignature;

    EicarTestSignature.md5 = "44d88612fea8a8f36de82e1278abb02";
    EicarTestSignature.name = "Eicar-Test-Signature";

    if (filehash == EicarTestSignature.md5)
    {
      return  EicarTestSignature.name;
    }

    Database::Malware HTMLGrimeawA;

    HTMLGrimeawA.md5 = "0A45af3e1963f277b05bda7eb68534fc";
    HTMLGrimeawA.name = "HTML/Grimeaw.A";

    if (filehash == HTMLGrimeawA.md5)
    {
      return  HTMLGrimeawA.name;
    }

    Database::Malware HTMLFakeAVSS;

    HTMLFakeAVSS.md5 = "062eb93577971cdd02d72dc231d1416a";
    HTMLFakeAVSS.name = "HTML/FakeAV.SS";

    if (filehash == HTMLFakeAVSS.md5)
    {
      return  HTMLFakeAVSS.name;
    }

    Database::Malware HTMLDldrFakeAVK;

    HTMLDldrFakeAVK.md5 = "999f232d282d547567a97a48d958ff21";
    HTMLDldrFakeAVK.name = "HTML/Dldr.FakeAV.K";

    if (filehash == HTMLDldrFakeAVK.md5)
    {
      return  HTMLDldrFakeAVK.name;
    }

    Database::Malware HTMLBandomB3;

    HTMLBandomB3.md5 = "5a6915fb58e73870e382c4af815595b7";
    HTMLBandomB3.name = "HTML/Bandom.B.3";

    if (filehash == HTMLBandomB3.md5)
    {
      return  HTMLBandomB3.name;
    }

    Database::Malware HTMLFakeAVK;

    HTMLFakeAVK.md5 = "0d08ae8b67235da016ee8b093fe09a16";
    HTMLFakeAVK.name = "HTML/FakeAV.K";

    if (filehash == HTMLFakeAVK.md5)
    {
      return  HTMLFakeAVK.name;
    }

    Database::Malware HTMLGericoffd;

    HTMLGericoffd.md5 = "7b991128acc7a9d306bcc296afe126cc";
    HTMLGericoffd.name = "HTML/Gerico.ffd";

    if (filehash == HTMLGericoffd.md5)
    {
      return  HTMLGericoffd.name;
    }

    Database::Malware HTMLDldrDawnA;

    HTMLDldrDawnA.md5 = "54bcb29dbcf60Abfba07fbb3735c0848";
    HTMLDldrDawnA.name = "HTML/Dldr.Dawn.A";

    if (filehash == HTMLDldrDawnA.md5)
    {
      return  HTMLDldrDawnA.name;
    }

    Database::Malware HTMLRedirectorBV;

    HTMLRedirectorBV.md5 = "3818ee712d9e52063c194e3a9ab65d33";
    HTMLRedirectorBV.name = "HTML/Redirector.BV";

    if (filehash == HTMLRedirectorBV.md5)
    {
      return  HTMLRedirectorBV.name;
    }

    Database::Malware HTMLVaejA;

    HTMLVaejA.md5 = "7245536ece184adfeb8468b6ac196b1d";
    HTMLVaejA.name = "HTML/Vaej.A";

    if (filehash == HTMLVaejA.md5)
    {
      return  HTMLVaejA.name;
    }

    Database::Malware HTMLSmallAE;

    HTMLSmallAE.md5 = "ac6edd8622d9fc440B37aa84bcb600e0";
    HTMLSmallAE.name = "HTML/Small.AE";

    if (filehash == HTMLSmallAE.md5)
    {
      return  HTMLSmallAE.name;
    }

    Database::Malware HTMLDldrIframeDC;

    HTMLDldrIframeDC.md5 = "179fc66cb6667320cddc946166dfc8e6";
    HTMLDldrIframeDC.name = "HTML/Dldr.Iframe.DC";

    if (filehash == HTMLDldrIframeDC.md5)
    {
      return  HTMLDldrIframeDC.name;
    }

    Database::Malware HTMLDownloaderI;

    HTMLDownloaderI.md5 = "1ea0c3b28617e667e588d667e4712bd9";
    HTMLDownloaderI.name = "HTML/Downloader.I";

    if (filehash == HTMLDownloaderI.md5)
    {
      return  HTMLDownloaderI.name;
    }

    Database::Malware HTMLDldrAgen2154;

    HTMLDldrAgen2154.md5 = "f09f564b1337970C7dcd8c134e859994";
    HTMLDldrAgen2154.name = "HTML/Dldr.Agen.2154";

    if (filehash == HTMLDldrAgen2154.md5)
    {
      return  HTMLDldrAgen2154.name;
    }

    Database::Malware HTMLDldrAg2185A;

    HTMLDldrAg2185A.md5 = "4f04cd3c4552f760337810d703ee55d1";
    HTMLDldrAg2185A.name = "HTML/Dldr.Ag.2185.A";

    if (filehash == HTMLDldrAg2185A.md5)
    {
      return  HTMLDldrAg2185A.name;
    }

    Database::Malware HTMLDldrAg2185B;

    HTMLDldrAg2185B.md5 = "014530f744d90896ec392be2f9fee6c8";
    HTMLDldrAg2185B.name = "HTML/Dldr.Ag.2185.B";

    if (filehash == HTMLDldrAg2185B.md5)
    {
      return  HTMLDldrAg2185B.name;
    }

    Database::Malware HTMLDldrFeebGV2;

    HTMLDldrFeebGV2.md5 = "f33d5b2d4f29eba19fedcfa496121368";
    HTMLDldrFeebGV2.name = "HTML/Dldr.Feeb.GV.2";

    if (filehash == HTMLDldrFeebGV2.md5)
    {
      return  HTMLDldrFeebGV2.name;
    }

    Database::Malware HTMLDropFeebGT2;

    HTMLDropFeebGT2.md5 = "4a0Ad9d136f004a28cbc8b72d279800C";
    HTMLDropFeebGT2.name = "HTML/Drop.Feeb.GT.2";

    if (filehash == HTMLDropFeebGT2.md5)
    {
      return  HTMLDropFeebGT2.name;
    }

    Database::Malware HTMLDropFeebs2;

    HTMLDropFeebs2.md5 = "70da69f2b921fe958c28c7ef8c76c4e0";
    HTMLDropFeebs2.name = "HTML/Drop.Feebs.2";

    if (filehash == HTMLDropFeebs2.md5)
    {
      return  HTMLDropFeebs2.name;
    }

    Database::Malware INFAutoRun288;

    INFAutoRun288.md5 = "fb44a22a455d237a1277b1cdcf07e598";
    INFAutoRun288.name = "INF/AutoRun.288";

    if (filehash == INFAutoRun288.md5)
    {
      return  INFAutoRun288.name;
    }

    Database::Malware IRCIrsda;

    IRCIrsda.md5 = "852ba2f14253f8c14ed8b2cceda522df";
    IRCIrsda.name = "IRC/Irsd.a";

    if (filehash == IRCIrsda.md5)
    {
      return  IRCIrsda.name;
    }

    Database::Malware JAVAPrunoF;

    JAVAPrunoF.md5 = "DD17FE9AC6227628CA08B23CCDB4312F";
    JAVAPrunoF.name = "JAVA/Pruno.F";

    if (filehash == JAVAPrunoF.md5)
    {
      return  JAVAPrunoF.name;
    }

    Database::Malware JSBlacolepsah;

    JSBlacolepsah.md5 = "bdf7d1e2e806fd3673e964e7dd181a9f";
    JSBlacolepsah.name = "JS/Blacole.psah";

    if (filehash == JSBlacolepsah.md5)
    {
      return  JSBlacolepsah.name;
    }

    Database::Malware JAVAFesterJ;

    JAVAFesterJ.md5 = "3e3a6b7ca42a3c63c86780a99fafec9b";
    JAVAFesterJ.name = "JAVA/Fester.J";

    if (filehash == JAVAFesterJ.md5)
    {
      return  JAVAFesterJ.name;
    }

    Database::Malware JOKEButtonsA11;

    JOKEButtonsA11.md5 = "ca7eb759152b48cc2c4a4bb4d2a170af";
    JOKEButtonsA11.name = "JOKE/Buttons.A.11";

    if (filehash == JOKEButtonsA11.md5)
    {
      return  JOKEButtonsA11.name;
    }

    Database::Malware JAVADldrTharraB;

    JAVADldrTharraB.md5 = "bb645151e2bdb03f91e2500e1bfbf0be";
    JAVADldrTharraB.name = "JAVA/Dldr.Tharra.B";

    if (filehash == JAVADldrTharraB.md5)
    {
      return  JAVADldrTharraB.name;
    }

    Database::Malware JSGargamelss1;

    JSGargamelss1.md5 = "777926d0b0f555463e1abb84bc20f14c";
    JSGargamelss1.name = "JS/Gargamel.ss.1";

    if (filehash == JSGargamelss1.md5)
    {
      return  JSGargamelss1.name;
    }

    Database::Malware JAVAExdoerCA;

    JAVAExdoerCA.md5 = "160a3879f9e7323ae7e9af1fc3b2c926";
    JAVAExdoerCA.name = "JAVA/Exdoer.CA";

    if (filehash == JAVAExdoerCA.md5)
    {
      return  JAVAExdoerCA.name;
    }

    Database::Malware JAVAExdoerCH;

    JAVAExdoerCH.md5 = "4dd0df10dbc4c34b270237e8926c2290";
    JAVAExdoerCH.name = "JAVA/Exdoer.CH";

    if (filehash == JAVAExdoerCH.md5)
    {
      return  JAVAExdoerCH.name;
    }

    Database::Malware JAVAExdoerCE;

    JAVAExdoerCE.md5 = "ea8a43a73a042ccd1175c7b360d480a1";
    JAVAExdoerCE.name = "JAVA/Exdoer.CE";

    if (filehash == JAVAExdoerCE.md5)
    {
      return  JAVAExdoerCE.name;
    }

    Database::Malware JAVAExploitBytverify4;

    JAVAExploitBytverify4.md5 = "5d575201dba8edace1071e2541f3388b";
    JAVAExploitBytverify4.name = "JAVA/Exploit.Bytverify.4";

    if (filehash == JAVAExploitBytverify4.md5)
    {
      return  JAVAExploitBytverify4.name;
    }

    Database::Malware JAVAAgent13073;

    JAVAAgent13073.md5 = "849a9adfed2ad701b3f5f6450e5abada";
    JAVAAgent13073.name = "JAVA/Agent.13073";

    if (filehash == JAVAAgent13073.md5)
    {
      return  JAVAAgent13073.name;
    }

    Database::Malware JAVAExdoerCF;

    JAVAExdoerCF.md5 = "4379a5fb7b05f5ea707d0742025a2b9b";
    JAVAExdoerCF.name = "JAVA/Exdoer.CF";

    if (filehash == JAVAExdoerCF.md5)
    {
      return  JAVAExdoerCF.name;
    }

    Database::Malware JAVADjewersN;

    JAVADjewersN.md5 = "a9e29171b2e58d35190bda244c036159";
    JAVADjewersN.name = "JAVA/Djewers.N";

    if (filehash == JAVADjewersN.md5)
    {
      return  JAVADjewersN.name;
    }

    Database::Malware JAVASmallAJ;

    JAVASmallAJ.md5 = "2c69dbb818a8a2b78770f90e363dc060";
    JAVASmallAJ.name = "JAVA/Small.AJ";

    if (filehash == JAVASmallAJ.md5)
    {
      return  JAVASmallAJ.name;
    }

    Database::Malware JAVAExdoerBS;

    JAVAExdoerBS.md5 = "f111b230148018a31a9bd925dc0682c0";
    JAVAExdoerBS.name = "JAVA/Exdoer.BS";

    if (filehash == JAVAExdoerBS.md5)
    {
      return  JAVAExdoerBS.name;
    }

    Database::Malware JAVAExdoerCV1;

    JAVAExdoerCV1.md5 = "c24417f9d2fc0d6143325031192d8c42";
    JAVAExdoerCV1.name = "JAVA/Exdoer.CV.1";

    if (filehash == JAVAExdoerCV1.md5)
    {
      return  JAVAExdoerCV1.name;
    }

    Database::Malware JAVAStutterAC;

    JAVAStutterAC.md5 = "71dd3619bf3d299d34c132ce5b30d291";
    JAVAStutterAC.name = "JAVA/Stutter.AC";

    if (filehash == JAVAStutterAC.md5)
    {
      return  JAVAStutterAC.name;
    }

    Database::Malware JAVAExdoerCC;

    JAVAExdoerCC.md5 = "0469bd9ac899c8333811390e6523ff6c";
    JAVAExdoerCC.name = "JAVAExdoerCC";

    if (filehash == JAVAExdoerCC.md5)
    {
      return  JAVAExdoerCC.name;
    }

    Database::Malware JAVAExdoerCT3;

    JAVAExdoerCT3.md5 = "6b18addf24aad6f8daf85d5676debf0b";
    JAVAExdoerCT3.name = "JAVA/Exdoer.CT.3";

    if (filehash == JAVAExdoerCT3.md5)
    {
      return  JAVAExdoerCT3.name;
    }

    Database::Malware JAVAPayLoadD;

    JAVAPayLoadD.md5 = "ccbd59c0f870283b07657df4cad0ddc5";
    JAVAPayLoadD.name = "JAVA/PayLoad.D";

    if (filehash == JAVAPayLoadD.md5)
    {
      return  JAVAPayLoadD.name;
    }

    Database::Malware JAVAExdoerCS3;

    JAVAExdoerCS3.md5 = "25a70900c690ccdd8171caf949a82afa";
    JAVAExdoerCS3.name = "JAVA/Exdoer.CS.3";

    if (filehash == JAVAExdoerCS3.md5)
    {
      return  JAVAExdoerCS3.name;
    }

    Database::Malware JAVAExdoerBZ;

    JAVAExdoerBZ.md5 = "689a65ab7dbb98839ae7e4ad1e606d1f";
    JAVAExdoerBZ.name = "JAVA/Exdoer.BZ";

    if (filehash == JAVAExdoerBZ.md5)
    {
      return  JAVAExdoerBZ.name;
    }

    Database::Malware JAVAFesterB1;

    JAVAFesterB1.md5 = "c52d28c502b64b04484f835bde114f09";
    JAVAFesterB1.name = "JAVA/Fester.B.1";

    if (filehash == JAVAFesterB1.md5)
    {
      return  JAVAFesterB1.name;
    }

    Database::Malware JavaDldrScudsA;

    JavaDldrScudsA.md5 = "4b5b1de7204c89e781c175f20Fafd8fd";
    JavaDldrScudsA.name = "Java/Dldr.Scuds.A";

    if (filehash == JavaDldrScudsA.md5)
    {
      return  JavaDldrScudsA.name;
    }

    Database::Malware JAVAStutterAG;

    JAVAStutterAG.md5 = "a82c27705af911a23554082293426062";
    JAVAStutterAG.name = "JAVA/Stutter.AG";

    if (filehash == JAVAStutterAG.md5)
    {
      return  JAVAStutterAG.name;
    }

    Database::Malware JSAgentUO1;

    JSAgentUO1.md5 = "e0d093a6ef5997d5eb0D5aca8a27cc5a";
    JSAgentUO1.name = "JS/Agent.UO.1";

    if (filehash == JSAgentUO1.md5)
    {
      return  JSAgentUO1.name;
    }

    Database::Malware JAVAFesterA;

    JAVAFesterA.md5 = "4186ef963b21e90bd2ef71df558673d0";
    JAVAFesterA.name = "JAVA/Fester.A";

    if (filehash == JAVAFesterA.md5)
    {
      return  JAVAFesterA.name;
    }

    Database::Malware JAVAAgentKB;

    JAVAAgentKB.md5 = "5801231f1c5efeba1c64b415ad7d37bf";
    JAVAAgentKB.name = "JAVA/Agent.KB";

    if (filehash == JAVAAgentKB.md5)
    {
      return  JAVAAgentKB.name;
    }

    Database::Malware JAVAAgentKF;

    JAVAAgentKF.md5 = "6dc4d4c5b98f3db269a05e9f274deb6b";
    JAVAAgentKF.name = "JAVA/Agent.KF";

    if (filehash == JAVAAgentKF.md5)
    {
      return  JAVAAgentKF.name;
    }

    Database::Malware JAVAAgent1151;

    JAVAAgent1151.md5 = "78ef5386ccba1ffb45aad644a288a487";
    JAVAAgent1151.name = "JAVA/Agent.1151";

    if (filehash == JAVAAgent1151.md5)
    {
      return  JAVAAgent1151.name;
    }

    Database::Malware JAVAStutterAA;

    JAVAStutterAA.md5 = "8696204264e95483825618263e74cc90";
    JAVAStutterAA.name = "JAVA/Stutter.AA";

    if (filehash == JAVAStutterAA.md5)
    {
      return  JAVAStutterAA.name;
    }

    Database::Malware JSPerplexB;

    JSPerplexB.md5 = "4f2f5252057b20b5a27f212bb68301bc";
    JSPerplexB.name = "JS/Perplex.B";

    if (filehash == JSPerplexB.md5)
    {
      return  JSPerplexB.name;
    }

    Database::Malware JAVAStutterZ;

    JAVAStutterZ.md5 = "cc669f4cb6ca12cb46e3750680e5e2f5";
    JAVAStutterZ.name = "JAVA/Stutter.Z";

    if (filehash == JAVAStutterZ.md5)
    {
      return  JAVAStutterZ.name;
    }

    Database::Malware JAVAAgentJT;

    JAVAAgentJT.md5 = "49978668e4dd0eea50d859ae7a2ac5f4";
    JAVAAgentJT.name = "JAVA/Agent.JT";

    if (filehash == JAVAAgentJT.md5)
    {
      return  JAVAAgentJT.name;
    }

    Database::Malware JAVAExdoerBD;

    JAVAExdoerBD.md5 = "7a39ede33ba6f44917b2876fb7a7ce5e";
    JAVAExdoerBD.name = "JAVA/Exdoer.BD";

    if (filehash == JAVAExdoerBD.md5)
    {
      return  JAVAExdoerBD.name;
    }

    Database::Malware JAVARedBrowserA1;

    JAVARedBrowserA1.md5 = "	1aab76767f76396b97e7363da714f39f";
    JAVARedBrowserA1.name = "JAVA/RedBrowser.A.1";

    if (filehash == JAVARedBrowserA1.md5)
    {
      return  JAVARedBrowserA1.name;
    }

    Database::Malware 	JAVAExdoerBL;

    JAVAExdoerBL.md5 = "c2863d0020c3ae50ab3c719155e04270";
    JAVAExdoerBL.name = "JAVA/Exdoer.BL";

    if (filehash == JAVAExdoerBL.md5)
    {
      return  JAVAExdoerBL.name;
    }

    Database::Malware JAVAStutterX;

    JAVAStutterX.md5 = "763f7369ff15651a07a810a4b5f45daf";
    JAVAStutterX.name = "JAVA/Stutter.X";

    if (filehash == JAVAStutterX.md5)
    {
      return  JAVAStutterX.name;
    }

    Database::Malware JSRedirectorKQ;

    JSRedirectorKQ.md5 = "103110222da6f86321daceba81e6b6de";
    JSRedirectorKQ.name = "JS/Redirector.KQ";

    if (filehash == JSRedirectorKQ.md5)
    {
      return  JSRedirectorKQ.name;
    }

    Database::Malware JAVAExdoerP2;

    JAVAExdoerP2.md5 = "595cf7c60821611d0a06f5c367e7d2ee";
    JAVAExdoerP2.name = "JAVA/Exdoer.P.2";

    if (filehash == JAVAExdoerP2.md5)
    {
      return  JAVAExdoerP2.name;
    }

    Database::Malware JAVAExdoerBJ4;

    JAVAExdoerBJ4.md5 = "b2ca20798090ebffe06d000C930De223";
    JAVAExdoerBJ4.name = "JAVA/Exdoer.BJ.4";

    if (filehash == JAVAExdoerBJ4.md5)
    {
      return  JAVAExdoerBJ4.name;
    }

    Database::Malware JAVAExdoerBK3;

    JAVAExdoerBK3.md5 = "bc88c9543ae453e96a7f5c937d43a93a";
    JAVAExdoerBK3.name = "JAVA/Exdoer.BK.3";

    if (filehash == JAVAExdoerBK3.md5)
    {
      return  JAVAExdoerBK3.name;
    }

    Database::Malware JSAgentahf;

    JSAgentahf.md5 = "3991ffa06b5f3d0b1ada69551a05ec60";
    JSAgentahf.name = "JS/Agent.ahf";

    if (filehash == JSAgentahf.md5)
    {
      return  JSAgentahf.name;
    }

    Database::Malware JAVAStutterT;

    JAVAStutterT.md5 = "ff7958fbb90f40957524633aa213c18e";
    JAVAStutterT.name = "JAVA/Stutter.T";

    if (filehash == JAVAStutterT.md5)
    {
      return  JAVAStutterT.name;
    }

    Database::Malware JAVAGunLaidC;

    JAVAGunLaidC.md5 = "8d349dc948d624ccb76cb3710b575ded";
    JAVAGunLaidC.name = "JAVA/GunLaid.C";

    if (filehash == JAVAGunLaidC.md5)
    {
      return  JAVAGunLaidC.name;
    }

    Database::Malware JAVAMundGuraD;

    JAVAMundGuraD.md5 = "e29df5e57692d1c9e8a66d8b22ebb782";
    JAVAMundGuraD.name = "JAVA/MundGura.D";

    if (filehash == JAVAMundGuraD.md5)
    {
      return  JAVAMundGuraD.name;
    }

    Database::Malware JAVAOpenStreamM;

    JAVAOpenStreamM.md5 = "c627bda653828cab486e25842f205664";
    JAVAOpenStreamM.name = "JAVA/OpenStream.M";

    if (filehash == JAVAOpenStreamM.md5)
    {
      return  JAVAOpenStreamM.name;
    }

    Database::Malware JAVAStutterG;

    JAVAStutterG.md5 = "0d6df346f99c9845463f42164c43e2b4";
    JAVAStutterG.name = "JAVA/Stutter.G";

    if (filehash == JAVAStutterG.md5)
    {
      return  JAVAStutterG.name;
    }

    Database::Malware JAVAGunLaidF;

    JAVAGunLaidF.md5 = "f654987ff3294acbf1068400d48ae581";
    JAVAGunLaidF.name = "JAVA/GunLaid.F";

    if (filehash == JAVAGunLaidF.md5)
    {
      return  JAVAGunLaidF.name;
    }

    Database::Malware JAVAExdoerBJ2;

    JAVAExdoerBJ2.md5 = "63d4b1f39e786eb4c641a0db5f55a44d";
    JAVAExdoerBJ2.name = "JAVA/Exdoer.BJ.2";

    if (filehash == JAVAExdoerBJ2.md5)
    {
      return  JAVAExdoerBJ2.name;
    }

    Database::Malware JavaExdoerBN;

    JavaExdoerBN.md5 = "838fac504d1f1a1d279658091f1c1811";
    JavaExdoerBN.name = "Java/Exdoer.BN";

    if (filehash == JavaExdoerBN.md5)
    {
      return  JavaExdoerBN.name;
    }

    Database::Malware JAVAStutterI5;

    JAVAStutterI5.md5 = "e61b11b32e82a1d924d8db86a68ffd18";
    JAVAStutterI5.name = "JAVA/Stutter.I.5";

    if (filehash == JAVAStutterI5.md5)
    {
      return  JAVAStutterI5.name;
    }

    Database::Malware JAVAStutterS;

    JAVAStutterS.md5 = "12cf8d832aca6fa2067f35335cd33812";
    JAVAStutterS.name = "JAVA/Stutter.S";

    if (filehash == JAVAStutterS.md5)
    {
      return  JAVAStutterS.name;
    }

    Database::Malware JAVAExdoerQ;

    JAVAExdoerQ.md5 = "dbd2bda080cd83a44624e69ad4524811";
    JAVAExdoerQ.name = "JAVA/Exdoer.Q";

    if (filehash == JAVAExdoerQ.md5)
    {
      return  JAVAExdoerQ.name;
    }

    Database::Malware JAVAExdoerAC;

    JAVAExdoerAC.md5 = "3eb9f4290fd70a4b0ff6c0f56ba3ae57";
    JAVAExdoerAC.name = "JAVA/Exdoer.AC";

    if (filehash == JAVAExdoerAC.md5)
    {
      return  JAVAExdoerAC.name;
    }

    Database::Malware JSAgentagx1;

    JSAgentagx1.md5 = "05d7feb75d33e9d7cfea32e0b4b0df92";
    JSAgentagx1.name = "JS/Agent.agx.1";

    if (filehash == JSAgentagx1.md5)
    {
      return  JSAgentagx1.name;
    }

    Database::Malware JSDldrAgentafq;

    JSDldrAgentafq.md5 = "49975fe2804dfba409477a3d8b952e4d";
    JSDldrAgentafq.name = "JS/Dldr.Agent.afq";

    if (filehash == JSDldrAgentafq.md5)
    {
      return  JSDldrAgentafq.name;
    }

    Database::Malware JAVAGunLaidA;

    JAVAGunLaidA.md5 = "e1447d2c58320102d12ea1b84da0f832";
    JAVAGunLaidA.name = "JAVA/GunLaid.A";

    if (filehash == JAVAGunLaidA.md5)
    {
      return  JAVAGunLaidA.name;
    }

    Database::Malware JSDldrFakeAVD;

    JSDldrFakeAVD.md5 = "924718ac7273c8e13ca86972ac87824a";
    JSDldrFakeAVD.name = "JS/Dldr.FakeAV.D";

    if (filehash == JSDldrFakeAVD.md5)
    {
      return  JSDldrFakeAVD.name;
    }

    Database::Malware JAVAStutterI3;

    JAVAStutterI3.md5 = "e2328e17f24bd0f2e1b39846a36cf372";
    JAVAStutterI3.name = "JAVA/Stutter.I.3";

    if (filehash == JAVAStutterI3.md5)
    {
      return  JAVAStutterI3.name;
    }


    Database::Malware JAVAStutterK;

    JAVAStutterK.md5 = "4b7f582d0ed05397191102028e19fcd7";
    JAVAStutterK.name = "JAVA/Stutter.K";

    if (filehash == JAVAStutterK.md5)
    {
      return  JAVAStutterK.name;
    }

    Database::Malware JAVAExdoerR;

    JAVAExdoerR.md5 = "92d3ba9c6307bb2e84b045a0a2370986";
    JAVAExdoerR.name = "JAVA/Exdoer.R";

    if (filehash == JAVAExdoerR.md5)
    {
      return  JAVAExdoerR.name;
    }

    Database::Malware JavaExdoerBG6;

    JavaExdoerBG6.md5 = "305ce2526c3156709630f87324a22e8d";
    JavaExdoerBG6.name = "Java/Exdoer.BG.6";

    if (filehash == JavaExdoerBG6.md5)
    {
      return  JavaExdoerBG6.name;
    }


    Database::Malware JAVAPescJ;

    JAVAPescJ.md5 = "3cdde57ec41e3e593c37904524da192b";
    JAVAPescJ.name = "JAVA/Pesc.J";

    if (filehash == JAVAPescJ.md5)
    {
      return  JAVAPescJ.name;
    }

    Database::Malware JAVAExdoerBG;

    JAVAExdoerBG.md5 = "4bfb626bc8b791ffa4c23ca2c86a3029";
    JAVAExdoerBG.name = "JAVA/Exdoer.BG";

    if (filehash == JAVAExdoerBG.md5)
    {
      return  JAVAExdoerBG.name;
    }

    Database::Malware JAVAPescI;

    JAVAPescI.md5 = "fdb04f62d1f571c3f45dac96c5f1803f";
    JAVAPescI.name = "JAVA/Pesc.I";

    if (filehash == JAVAPescI.md5)
    {
      return  JAVAPescI.name;
    }

    Database::Malware JAVASenegalGF;

    JAVASenegalGF.md5 = "3ef639931766aca69ce0fc3c9efddd0d";
    JAVASenegalGF.name = "JAVA/Senegal.GF";

    if (filehash == JAVASenegalGF.md5)
    {
      return  JAVASenegalGF.name;
    }

    Database::Malware JAVADecouvertAS;

    JAVADecouvertAS.md5 = "ea6fc086fa44d14a0e5227a4a30637cb";
    JAVADecouvertAS.name = "JAVA/Decouvert.AS";

    if (filehash == JAVADecouvertAS.md5)
    {
      return  JAVADecouvertAS.name;
    }

    Database::Malware JAVASenekaB;

    JAVASenekaB.md5 = "c1848aac67e60976a51f9cd23916cb93";
    JAVASenekaB.name = "JAVA/Seneka.B";

    if (filehash == JAVASenekaB.md5)
    {
      return  JAVASenekaB.name;
    }

    Database::Malware JAVAExdoerBC1;

    JAVAExdoerBC1.md5 = "28d4e685944373d37ee66429752e96f2";
    JAVAExdoerBC1.name = "JAVA/Exdoer.BC.1";

    if (filehash == JAVAExdoerBC1.md5)
    {
      return  JAVAExdoerBC1.name;
    }


    Database::Malware JAVAExdoerBB3D;

    JAVAExdoerBB3D.md5 = "ace6b710faebe13be986be9ab31f9450";
    JAVAExdoerBB3D.name = "JAVA/Exdoer.BB.3.D";

    if (filehash == JAVAExdoerBB3D.md5)
    {
      return  JAVAExdoerBB3D.name;
    }


    Database::Malware JAVAOpenConnectK;

    JAVAOpenConnectK.md5 = "df3f4776f87776c4ec41f71e8be82b7b";
    JAVAOpenConnectK.name = "JAVA/OpenConnect.K";

    if (filehash == JAVAOpenConnectK.md5)
    {
      return  JAVAOpenConnectK.name;
    }


    Database::Malware JavaStutterI1;

    JavaStutterI1.md5 = "15af8a8389dd024f95e0af7cc0e53815";
    JavaStutterI1.name = "Java/Stutter.I.1";

    if (filehash == JavaStutterI1.md5)
    {
      return  JavaStutterI1.name;
    }

    Database::Malware JAVAExdoerBE2;

    JAVAExdoerBE2.md5 = "7d46b581a2c5447d36e4061bfffd18de";
    JAVAExdoerBE2.name = "JAVA/Exdoer.BE.2";

    if (filehash == JAVAExdoerBE2.md5)
    {
      return  JAVAExdoerBE2.name;
    }

    Database::Malware JAVAExdoerAJ;

    JAVAExdoerAJ.md5 = "f27e9743d3d7aff555f407b96cbea425";
    JAVAExdoerAJ.name = "JAVA/Exdoer.AJ";

    if (filehash == JAVAExdoerAJ.md5)
    {
      return  JAVAExdoerAJ.name;
    }


    Database::Malware JAVAStutterE;

    JAVAStutterE.md5 = "c45cb706ad3a1671cc9852f381e46366";
    JAVAStutterE.name = "JAVA/Stutter.E";

    if (filehash == JAVAStutterE.md5)
    {
      return  JAVAStutterE.name;
    }

    Database::Malware JAVAOpenConnectJ;

    JAVAOpenConnectJ.md5 = "547a930Ae03ee42618567d1206e92da7";
    JAVAOpenConnectJ.name = "JAVA/OpenConnect.J";

    if (filehash == JAVAOpenConnectJ.md5)
    {
      return  JAVAOpenConnectJ.name;
    }

    Database::Malware JAVAStutterD;

    JAVAStutterD.md5 = "7214f810ac5fc5d64af9a6c0e699433b";
    JAVAStutterD.name = "JAVA/Stutter.D";

    if (filehash == JAVAStutterD.md5)
    {
      return  JAVAStutterD.name;
    }

    Database::Malware JAVAExdoerY;

    JAVAExdoerY.md5 = "b27e5555e188d5f70252ecfd4400aaca";
    JAVAExdoerY.name = "JAVA/Exdoer.Y";

    if (filehash == JAVAExdoerY.md5)
    {
      return  JAVAExdoerY.name;
    }


    Database::Malware JAVAExdoerZ;

    JAVAExdoerZ.md5 = "be91566ce04a8f57037c8288ddf3e6b5";
    JAVAExdoerZ.name = "JAVA/Exdoer.Z";

    if (filehash == JAVAExdoerZ.md5)
    {
      return  JAVAExdoerZ.name;
    }


    Database::Malware JAVAExdoerO;

    JAVAExdoerO.md5 = "573b84753f067a2fffb885f37df72d19";
    JAVAExdoerO.name = "JAVA/Exdoer.O";

    if (filehash == JAVAExdoerO.md5)
    {
      return  JAVAExdoerO.name;
    }


    Database::Malware JAVAExdoerF;

    JAVAExdoerF.md5 = "3a93b186d383218b94dd3100be62ba93";
    JAVAExdoerF.name = "JAVA/Exdoer.F";

    if (filehash == JAVAExdoerF.md5)
    {
      return  JAVAExdoerF.name;
    }


    Database::Malware 	JAVAExdoerH;

    JAVAExdoerH.md5 = "a2ef213569671872716e955ff4f69264";
    JAVAExdoerH.name = "JAVA/Exdoer.H";

    if (filehash == JAVAExdoerH.md5)
    {
      return  JAVAExdoerH.name;
    }


    Database::Malware JAVAAgentJJ;

    JAVAAgentJJ.md5 = "d765cac15cbfee0340e1f834d4a8cb05";
    JAVAAgentJJ.name = "JAVA/Agent.JJ";

    if (filehash == JAVAAgentJJ.md5)
    {
      return  JAVAAgentJJ.name;
    }


    Database::Malware JAVAExdoerI;

    JAVAExdoerI.md5 = "b8e8fbc856374aadd719dd48bca38a0F";
    JAVAExdoerI.name = "JAVA/Exdoer.I";

    if (filehash == JAVAExdoerI.md5)
    {
      return  JAVAExdoerI.name;
    }

    Database::Malware JAVAOpenStreamL;

    JAVAOpenStreamL.md5 = "c547fa0Dac55cc861fe5aad71fe81c9a";
    JAVAOpenStreamL.name = "JAVA/OpenStream.L";

    if (filehash == JAVAOpenStreamL.md5)
    {
      return  JAVAOpenStreamL.name;
    }

    Database::Malware JAVAOpenConnectE;

    JAVAOpenConnectE.md5 = "c64991658c348288d62ffd644dda01dc";
    JAVAOpenConnectE.name = "JAVA/OpenConnect.E";

    if (filehash == JAVAOpenConnectE.md5)
    {
      return  JAVAOpenConnectE.name;
    }

    Database::Malware JAVASmallAF;

    JAVASmallAF.md5 = "bdd74c059d071b002ad686a70E5a920A";
    JAVASmallAF.name = "JAVA/Small.AF";

    if (filehash == JAVASmallAF.md5)
    {
      return  JAVASmallAF.name;
    }

    Database::Malware JAVAExdoerB;

    JAVAExdoerB.md5 = "284d62bd1418a509b42b416fa20B2e03";
    JAVAExdoerB.name = "JAVA/Exdoer.B";

    if (filehash == JAVAExdoerB.md5)
    {
      return  JAVAExdoerB.name;
    }

    Database::Malware JAVAExdoerC;

    JAVAExdoerC.md5 = "b8a7eab273e1002234fcf73d40825bb1";
    JAVAExdoerC.name = "JAVA/Exdoer.C";

    if (filehash == JAVAExdoerC.md5)
    {
      return  JAVAExdoerC.name;
    }

    Database::Malware JAVAExdoerA;

    JAVAExdoerA.md5 = "1dcad9dc810da4c90f28f4412681d1d6";
    JAVAExdoerA.name = "JAVA/Exdoer.A";

    if (filehash == JAVAExdoerA.md5)
    {
      return  JAVAExdoerA.name;
    }

    Database::Malware JAVASmallZ;

    JAVASmallZ.md5 = "3b9965c8d3821fa9b6e92baed2247843";
    JAVASmallZ.name = "JAVA/Small.Z";

    if (filehash == JAVASmallZ.md5)
    {
      return  JAVASmallZ.name;
    }

    Database::Malware JSDldrAgentaeq;

    JSDldrAgentaeq.md5 = "4905f7a51c597c359f938f7f8a16eda2";
    JSDldrAgentaeq.name = "JS/Dldr.Agent.aeq";

    if (filehash == JSDldrAgentaeq.md5)
    {
      return  JSDldrAgentaeq.name;
    }

    Database::Malware JAVAAgentJG;

    JAVAAgentJG.md5 = "03a7a51808d6c73a64ff954f15b5d029";
    JAVAAgentJG.name = "JAVA/Agent.JG";

    if (filehash == JAVAAgentJG.md5)
    {
      return  JAVAAgentJG.name;
    }

    Database::Malware JAVAClassLoaderAH;

    JAVAClassLoaderAH.md5 = "8369c41186f02a51f43d96e51e132477";
    JAVAClassLoaderAH.name = "JAVA/ClassLoader.AH";

    if (filehash == JAVAClassLoaderAH.md5)
    {
      return  JAVAClassLoaderAH.name;
    }

    Database::Malware JSiFrame6799;

    JSiFrame6799.md5 = "fb4018cf0419ac4bac9ac9b9ad8ac5ac";
    JSiFrame6799.name = "JS/iFrame.6799";

    if (filehash == JSiFrame6799.md5)
    {
      return  JSiFrame6799.name;
    }

    Database::Malware JAVADldrOpenSNBG;

    JAVADldrOpenSNBG.md5 = "ce2b288462011a182940128323ffd979";
    JAVADldrOpenSNBG.name = "JAVA/Dldr.OpenS.NBG";

    if (filehash == JAVADldrOpenSNBG.md5)
    {
      return  JAVADldrOpenSNBG.name;
    }

    Database::Malware JAVAOpenConnectDD;

    JAVAOpenConnectDD.md5 = "7f674d2a23ce997b6dcb12b5b2fc28d6";
    JAVAOpenConnectDD.name = "JAVA/OpenConnect.DD";

    if (filehash == JAVAOpenConnectDD.md5)
    {
      return  JAVAOpenConnectDD.name;
    }

    Database::Malware JAVAAgentX1;

    JAVAAgentX1.md5 = "7b4acb58ac3698641a2b84bba357768d";
    JAVAAgentX1.name = "JAVA/Agent.X.1";

    if (filehash == JAVAAgentX1.md5)
    {
      return  JAVAAgentX1.name;
    }

    Database::Malware JAVARastA;

    JAVARastA.md5 = "c593c969da11d619ebc4583180322bbb";
    JAVARastA.name = "JAVA/Rast.A";

    if (filehash == JAVARastA.md5)
    {
      return  JAVARastA.name;
    }

    Database::Malware JAVADldrAgentcas;

    JAVADldrAgentcas.md5 = "ead3c8ed4aa4808c10baa0bf49e068bf";
    JAVADldrAgentcas.name = "JAVA/Dldr.Agent.cas";

    if (filehash == JAVADldrAgentcas.md5)
    {
      return  JAVADldrAgentcas.name;
    }

    Database::Malware JAVAAgent2967;

    JAVAAgent2967.md5 = "4fca230D8b362ff9fc1ab3874ed258e0";
    JAVAAgent2967.name = "JAVA/Agent.2967";

    if (filehash == JAVAAgent2967.md5)
    {
      return  JAVAAgent2967.name;
    }

    Database::Malware JavaDldrAgentY;

    JavaDldrAgentY.md5 = "e9d89b71e6616841121d0A84c95263e6";
    JavaDldrAgentY.name = "Java/Dldr.Agent.Y";

    if (filehash == JavaDldrAgentY.md5)
    {
      return  JavaDldrAgentY.name;
    }

    Database::Malware JAVAOpenStreamF;

    JAVAOpenStreamF.md5 = "e68871774db27579aead7ff8d9da6ab7";
    JAVAOpenStreamF.name = "JAVA/OpenStream.F";

    if (filehash == JAVAOpenStreamF.md5)
    {
      return  JAVAOpenStreamF.name;
    }

    Database::Malware JavaAppletK;

    JavaAppletK.md5 = "266f4a8ed4b41a10a847143b679c18a5";
    JavaAppletK.name = "Java/Applet.K";

    if (filehash == JavaAppletK.md5)
    {
      return  JavaAppletK.name;
    }

    Database::Malware JavaOpenConnectAL;

    JavaOpenConnectAL.md5 = "ef02ee6d7de05058ce22bb73573b7ed4";
    JavaOpenConnectAL.name = "Java/OpenConnect.AL";

    if (filehash == JavaOpenConnectAL.md5)
    {
      return  JavaOpenConnectAL.name;
    }

    Database::Malware JavaDldrAgentAF;

    JavaDldrAgentAF.md5 = "bd7d2619b7816e1e6720542f62df5ff0";
    JavaDldrAgentAF.name = "Java/Dldr.Agent.AF";

    if (filehash == JavaDldrAgentAF.md5)
    {
      return  JavaDldrAgentAF.name;
    }

    Database::Malware JavaOpenConneAI1;

    JavaOpenConneAI1.md5 = "c545c2b80F0E0C3d9d6cd6ae4ece5d6e";
    JavaOpenConneAI1.name = "Java/OpenConne.AI.1";

    if (filehash == JavaOpenConneAI1.md5)
    {
      return  JavaOpenConneAI1.name;
    }

    Database::Malware JavaRemoteC;

    JavaRemoteC.md5 = "44afb97e7fe0c31bb65e8d501f4713f2";
    JavaRemoteC.name = "Java/Remote.C";

    if (filehash == JavaRemoteC.md5)
    {
      return  JavaRemoteC.name;
    }

    Database::Malware JavaOpenConnectAI;

    JavaOpenConnectAI.md5 = "bffb79de6c7d67cd32d8b7d19d1405fc";
    JavaOpenConnectAI.name = "Java/OpenConnect.AI";

    if (filehash == JavaOpenConnectAI.md5)
    {
      return  JavaOpenConnectAI.name;
    }

    Database::Malware JavaOpenConnectCA;

    JavaOpenConnectCA.md5 = "f53da2ae21d93e12e10De65ce228b0d8";
    JavaOpenConnectCA.name = "Java/OpenConnect.CA";

    if (filehash == JavaOpenConnectCA.md5)
    {
      return  JavaOpenConnectCA.name;
    }

    Database::Malware JavaAgentAD1;

    JavaAgentAD1.md5 = "744d57ac9248e09f87f5ae058815bae2";
    JavaAgentAD1.name = "Java/Agent.AD.1";

    if (filehash == JavaAgentAD1.md5)
    {
      return  JavaAgentAD1.name;
    }

    Database::Malware JAVASmallAC;

    JAVASmallAC.md5 = "e6d648ada581c75859a4e7cb7556a55a";
    JAVASmallAC.name = "JAVA/Small.AC";

    if (filehash == JAVASmallAC.md5)
    {
      return  JAVASmallAC.name;
    }

    Database::Malware JSAgent30510;

    JSAgent30510.md5 = "2cbf13a6da1ea3ebfd993183f33db8d4";
    JSAgent30510.name = "JS/Agent.30510";

    if (filehash == JSAgent30510.md5)
    {
      return  JSAgent30510.name;
    }

    Database::Malware JAVAOpenConnectA;

    JAVAOpenConnectA.md5 = "c8a816c839a7efe06e61d590bdc4ce43";
    JAVAOpenConnectA.name = "JAVA/OpenConnect.A";

    if (filehash == JAVAOpenConnectA.md5)
    {
      return  JAVAOpenConnectA.name;
    }

    Database::Malware JAVAOpenConnectiC;

    JAVAOpenConnectiC.md5 = "dd50e8a2c60373c8b67a4c235fd8c069";
    JAVAOpenConnectiC.name = "JAVA/OpenConnecti.C";

    if (filehash == JAVAOpenConnectiC.md5)
    {
      return  JAVAOpenConnectiC.name;
    }

    Database::Malware JavaOpenConnectiB;

    JavaOpenConnectiB.md5 = "d2e690d99e23f245033c3a56e3e7cedd";
    JavaOpenConnectiB.name = "Java/OpenConnecti.B";

    if (filehash == JavaOpenConnectiB.md5)
    {
      return  JavaOpenConnectiB.name;
    }

    Database::Malware JAVASmallY;

    JAVASmallY.md5 = "fd9987ce8b982986f0280Ab35070c929";
    JAVASmallY.name = "JAVA/Small.Y";

    if (filehash == JAVASmallY.md5)
    {
      return  JAVASmallY.name;
    }

    Database::Malware JavaOpenConnectcf;

    JavaOpenConnectcf.md5 = "0C8103C60CBA7CFBF7418F7D10EC541C";
    JavaOpenConnectcf.name = "Java/OpenConnect.cf";

    if (filehash == JavaOpenConnectcf.md5)
    {
      return  JavaOpenConnectcf.name;
    }

    Database::Malware JavaClassLoadAK;

    JavaClassLoadAK.md5 = "c5e9a0d1fe5c07eabbd95c3744431ced";
    JavaClassLoadAK.name = "Java/ClassLoad.AK";

    if (filehash == JavaClassLoadAK.md5)
    {
      return  JavaClassLoadAK.name;
    }

    Database::Malware JavaAgentdu;

    JavaAgentdu.md5 = "d440320576487e1fc520f19f4cee6838";
    JavaAgentdu.name = "Java/Agent.du";

    if (filehash == JavaAgentdu.md5)
    {
      return  JavaAgentdu.name;
    }

    Database::Malware JAVAPescF;

    JAVAPescF.md5 = "6be834ff3a6e28197f253913d1fdace1";
    JAVAPescF.name = "JAVA/Pesc.F";

    if (filehash == JAVAPescF.md5)
    {
      return  JAVAPescF.name;
    }

    Database::Malware JavaOpenStreamG;

    JavaOpenStreamG.md5 = "E5DAD02B3D89F390E686E7567E4C51EC";
    JavaOpenStreamG.name = "Java/OpenStream.G";

    if (filehash == JavaOpenStreamG.md5)
    {
      return  JavaOpenStreamG.name;
    }

    Database::Malware JavaRowindalR;

    JavaRowindalR.md5 = "c57d285c2a6af1290E8e75032e8381b2";
    JavaRowindalR.name = "Java/Rowindal.R";

    if (filehash == JavaRowindalR.md5)
    {
      return  JavaRowindalR.name;
    }

    Database::Malware JSPidief21793;

    JSPidief21793.md5 = "abc9839239af0146d641583aabbe99c1";
    JSPidief21793.name = "JS/Pidief.21793";

    if (filehash == JSPidief21793.md5)
    {
      return  JSPidief21793.name;
    }

    Database::Malware JSiFrame3184;

    JSiFrame3184.md5 = "da81c58ce3b0b744d464a109321d0932";
    JSiFrame3184.name = "JS/iFrame.3184";

    if (filehash == JSiFrame3184.md5)
    {
      return  JSiFrame3184.name;
    }

    Database::Malware JavaAgentHR;

    JavaAgentHR.md5 = "af4f84cc6d3131fa5ecb8844f0817531";
    JavaAgentHR.name = "Java/Agent.HR";

    if (filehash == JavaAgentHR.md5)
    {
      return  JavaAgentHR.name;
    }

    Database::Malware JSDldr51laB;

    JSDldr51laB.md5 = "b2ff3028257bb95f7ad827ab95553a06";
    JSDldr51laB.name = "JS/Dldr.51la.B";

    if (filehash == JSDldr51laB.md5)
    {
      return  JSDldr51laB.name;
    }

    Database::Malware JavaAgent2212;

    JavaAgent2212.md5 = "248991681934f8024fa008d5173e80dc";
    JavaAgent2212.name = "Java/Agent.2212";

    if (filehash == JavaAgent2212.md5)
    {
      return JavaAgent2212.name;
    }

    Database::Malware JAVAAgentHN;

    JAVAAgentHN.md5 = "96a58b331c1b12d0202eafec0D92b44e";
    JAVAAgentHN.name = "JAVA/Agent.HN";

    if (filehash == JAVAAgentHN.md5)
    {
      return JAVAAgentHN.name;
    }

    Database::Malware JavaAgentFK;

    JavaAgentFK.md5 = "e52a94d474103ca47002f36e642c42df";
    JavaAgentFK.name = "Java/Agent.FK";

    if (filehash == JavaAgentFK.md5)
    {
      return JavaAgentFK.name;
    }

    Database::Malware JavaClassLoaderBO;

    JavaClassLoaderBO.md5 = "c9dea4f0a1ad21a6329e0Fc7d081c3cd";
    JavaClassLoaderBO.name = "Java/ClassLoader.BO";

    if (filehash == JavaClassLoaderBO.md5)
    {
      return JavaClassLoaderBO.name;
    }

    Database::Malware JavaC20093867EH;

    JavaC20093867EH.md5 = "c1e45dc473b3d44ab79e65f6c0669ebe";
    JavaC20093867EH.name = "Java/C-2009-3867.EH";

    if (filehash == JavaC20093867EH.md5)
    {
      return JavaC20093867EH.name;
    }

    Database::Malware JavaMailA;

    JavaMailA.md5 = "4cac2de8b27f948eeb9885ffaf21d846";
    JavaMailA.name = "Java/Mail.A";

    if (filehash == JavaMailA.md5)
    {
      return JavaMailA.name;
    }

    Database::Malware JavaAgentBC1;

    JavaAgentBC1.md5 = "ce48c8a97c7df46ec30C5384ab51b2dc";
    JavaAgentBC1.name = "Java/Agent.BC.1";

    if (filehash == JavaAgentBC1.md5)
    {
      return JavaAgentBC1.name;
    }

    Database::Malware JavaAgentBH;

    JavaAgentBH.md5 = "cbc69fa52ac8b7b808dd5154f64a8799";
    JavaAgentBH.name = "Java/Agent.BH";

    if (filehash == JavaAgentBH.md5)
    {
      return JavaAgentBH.name;
    }

    Database::Malware JavaOpenStreamA;

    JavaOpenStreamA.md5 = "0Db375cbcb0C856ad477491b8d3da49d";
    JavaOpenStreamA.name = "Java/OpenStream.A";

    if (filehash == JavaOpenStreamA.md5)
    {
      return JavaOpenStreamA.name;
    }

    Database::Malware JavaAgentAL3;

    JavaAgentAL3.md5 = "e505193feab05237513cdaf1645f12fe";
    JavaAgentAL3.name = "Java/Agent.AL.3";

    if (filehash == JavaAgentAL3.md5)
    {
      return JavaAgentAL3.name;
    }

    Database::Malware JavaAgentAJ4;

    JavaAgentAJ4.md5 = "c0d7892fc6f618b766848cbb0C80be8c";
    JavaAgentAJ4.name = "Java/Agent.AJ.4";

    if (filehash == JavaAgentAJ4.md5)
    {
      return JavaAgentAJ4.name;
    }

    Database::Malware JavaAgentDE1;

    JavaAgentDE1.md5 = "a128c26cf0d38f20c6fb8443ba6c24a9";
    JavaAgentDE1.name = "Java/Agent.DE.1";

    if (filehash == JavaAgentDE1.md5)
    {
      return JavaAgentDE1.name;
    }

    Database::Malware JavaRowindalC;

    JavaRowindalC.md5 = "8e20c48ebb84df21f3cba3ec101eaedc";
    JavaRowindalC.name = "Java/Rowindal.C";

    if (filehash == JavaRowindalC.md5)
    {
      return JavaRowindalC.name;
    }

    Database::Malware JavaClassLoaderAZ;

    JavaClassLoaderAZ.md5 = "48db4249c29704eb825ac1bbcb259822";
    JavaClassLoaderAZ.name = "Java/ClassLoader.AZ";

    if (filehash == JavaClassLoaderAZ.md5)
    {
      return JavaClassLoaderAZ.name;
    }

    Database::Malware JavaDldrAgentW;

    JavaDldrAgentW.md5 = "a653327d757a49a2f2d1f6fe07cb8014";
    JavaDldrAgentW.name = "Java/Dldr.Agent.W";

    if (filehash == JavaDldrAgentW.md5)
    {
      return JavaDldrAgentW.name;
    }

    Database::Malware JavaAgentAJ2;

    JavaAgentAJ2.md5 = "fff47d9c98c3e5841ccf2cdc5dd5b299";
    JavaAgentAJ2.name = "Java/Agent.AJ.2";

    if (filehash == JavaAgentAJ2.md5)
    {
      return JavaAgentAJ2.name;
    }

    Database::Malware JavaClassLoaderAB;

    JavaClassLoaderAB.md5 = "8aa1a8f89b155856f1f50De8c2ea9ad0";
    JavaClassLoaderAB.name = "Java/ClassLoader.AB";

    if (filehash == JavaClassLoaderAB.md5)
    {
      return JavaClassLoaderAB.name;
    }

    Database::Malware JavaClassloaderAX;

    JavaClassloaderAX.md5 = "2dc66c347376ea49d0a42a0E3972bb75";
    JavaClassloaderAX.name = "Java/Classloader.AX";

    if (filehash == JavaClassloaderAX.md5)
    {
      return JavaClassloaderAX.name;
    }

    Database::Malware JavaClassLoaderAV;

    JavaClassLoaderAV.md5 = "75cd73ffa7734f16797f28d9bf9846b3";
    JavaClassLoaderAV.name = "Java/ClassLoader.AV";

    if (filehash == JavaClassLoaderAV.md5)
    {
      return JavaClassLoaderAV.name;
    }

    Database::Malware JavaAgentFF;

    JavaAgentFF.md5 = "cfa6b08ee4d1e0177d6941fccfb043e6";
    JavaAgentFF.name = "Java/Agent.FF";

    if (filehash == JavaAgentFF.md5)
    {
      return JavaAgentFF.name;
    }


    Database::Malware JavaAgentAN;

    JavaAgentAN.md5 = "404e57c72fe12184c7f16862e638e53a";
    JavaAgentAN.name = "Java/Agent.AN";

    if (filehash == JavaAgentAN.md5)
    {
      return JavaAgentAN.name;
    }

    Database::Malware JavaAgentM3;

    JavaAgentM3.md5 = "4bd6e7fc232d4628bc9b7de7bc487f2d";
    JavaAgentM3.name = "Java/Agent.M.3";

    if (filehash == JavaAgentM3.md5)
    {
      return JavaAgentM3.name;
    }

    Database::Malware JavaAgentU;

    JavaAgentU.md5 = "63d23da6ea900A12a0139bc5b1b56f8f";
    JavaAgentU.name = "Java/Agent.U";

    if (filehash == JavaAgentU.md5)
    {
      return JavaAgentU.name;
    }

    Database::Malware JavaAgentAE;

    JavaAgentAE.md5 = "	b7d83626ca5badf386177deab6f00F50";
    JavaAgentAE.name = "Java/Agent.AE";

    if (filehash == JavaAgentAE.md5)
    {
      return JavaAgentAE.name;
    }

    Database::Malware JavaAgentAJ1;

    JavaAgentAJ1.md5 = "11c82f3130d066d184dedc559a482546";
    JavaAgentAJ1.name = "Java/Agent.AJ.1";

    if (filehash == JavaAgentAJ1.md5)
    {
      return JavaAgentAJ1.name;
    }

    Database::Malware JavaAgentAH;

    JavaAgentAH.md5 = "ccefc4dc0Cf9d7c9d0eed51190cdcbaa";
    JavaAgentAH.name = "Java/Agent.AH";

    if (filehash == JavaAgentAH.md5)
    {
      return JavaAgentAH.name;
    }

    Database::Malware JavaAgentM1;

    JavaAgentM1.md5 = "1991b482512f5416eeffda99739d3ea7";
    JavaAgentM1.name = "Java/Agent.M.1";

    if (filehash == JavaAgentM1.md5)
    {
      return JavaAgentM1.name;
    }

    Database::Malware JSRedirectork795;

    JSRedirectork795.md5 = "356643c5181015a123bc3c5651a6b566";
    JSRedirectork795.name = "JS/Redirector.k.795";

    if (filehash == JSRedirectork795.md5)
    {
      return JSRedirectork795.name;
    }

    Database::Malware JSRedirector455;

    JSRedirector455.md5 = "33b025c7942911f52ea3d81299c7b7db";
    JSRedirector455.name = "JS/Redirector.455";

    if (filehash == JSRedirector455.md5)
    {
      return JSRedirector455.name;
    }

    Database::Malware JAVADldrAgentG;

    JAVADldrAgentG.md5 = "c7e7a7a48f687fb8a0e5088cf974d757";
    JAVADldrAgentG.name = "JAVA/Dldr.Agent.G";

    if (filehash == JAVADldrAgentG.md5)
    {
      return JAVADldrAgentG.name;
    }

    Database::Malware JAVADldrSmallA;

    JAVADldrSmallA.md5 = "fd4aafa0ebb2ff23044985c5fb5bf9e1";
    JAVADldrSmallA.name = "JAVA/Dldr.Small.A";

    if (filehash == JAVADldrSmallA.md5)
    {
      return JAVADldrSmallA.name;
    }

    Database::Malware JSDldrAgentbbt;

    JSDldrAgentbbt.md5 = "e884eddfacac2cf7a38ab39b944baa31";
    JSDldrAgentbbt.name = "JS/Dldr.Agent.bbt";

    if (filehash == JSDldrAgentbbt.md5)
    {
      return JSDldrAgentbbt.name;
    }

    Database::Malware JSDldrAgentPR;

    JSDldrAgentPR.md5 = "7c71e464e76ae83b35557b552515422b";
    JSDldrAgentPR.name = "JS/Dldr.Agent.PR";

    if (filehash == JSDldrAgentPR.md5)
    {
      return JSDldrAgentPR.name;
    }

    Database::Malware JSDldrAgentbxi;

    JSDldrAgentbxi.md5 = "11a0262a27f140ecc4e9ddfc52306abc";
    JSDldrAgentbxi.name = "JS/Dldr.Agent.bxi";

    if (filehash == JSDldrAgentbxi.md5)
    {
      return JSDldrAgentbxi.name;
    }


    Database::Malware JSDldrAgentSI;

    JSDldrAgentSI.md5 = "7c44d3cf5013cf7405150493402bbcbd";
    JSDldrAgentSI.name = "JS/Dldr.Agent.SI";

    if (filehash == JSDldrAgentSI.md5)
    {
      return JSDldrAgentSI.name;
    }


    Database::Malware JSMimailB;

    JSMimailB.md5 = "8d77f783521465d63e4c9cc5595714fa";
    JSMimailB.name = "JS/Mimail.B";

    if (filehash == JSMimailB.md5)
    {
      return JSMimailB.name;
    }

    Database::Malware JokeRenosW;

    JokeRenosW.md5 = "fa7582def8348c22b69a4bb360eff64b";
    JokeRenosW.name = "Joke/Renos.W";

    if (filehash == JokeRenosW.md5)
    {
      return JokeRenosW.name;
    }

    Database::Malware PHISHStealingB;

    PHISHStealingB.md5 = "145CE660F7FD322DA17F16123EDD28DF";
    PHISHStealingB.name = "PHISH/Stealing.B";

    if (filehash == PHISHStealingB.md5)
    {
      return PHISHStealingB.name;
    }

    Database::Malware RKIT37704A;

    RKIT37704A.md5 = "6782a7b800d2be2064e6ca9377d704f6";
    RKIT37704A.name = "RKIT/37704.A";

    if (filehash == RKIT37704A.md5)
    {
      return RKIT37704A.name;
    }

    Database::Malware RKITAgentbiiu;

    RKITAgentbiiu.md5 = "0Bb8cf97b010ad4cbf8d0C14eabc9509";
    RKITAgentbiiu.name = "RKIT/Agent.biiu";

    if (filehash == RKITAgentbiiu.md5)
    {
      return RKITAgentbiiu.name;
    }

    Database::Malware RKitStuxnetA;

    RKitStuxnetA.md5 = "f8153747bae8b4ae48837ee17172151e";
    RKitStuxnetA.name = "RKit/Stuxnet.A";

    if (filehash == RKitStuxnetA.md5)
    {
      return RKitStuxnetA.name;
    }

    Database::Malware RkitAgentnfi;

    RkitAgentnfi.md5 = "02e1df5942f45880e7aae5adca701e6a";
    RkitAgentnfi.name = "Rkit/Agent.nfi";

    if (filehash == RkitAgentnfi.md5)
    {
      return RkitAgentnfi.name;
    }

    Database::Malware SPRWinHookA;

    SPRWinHookA.md5 = "57772362bcc5ecc4eb55ac3c401d2000";
    SPRWinHookA.name = "SPR/WinHook.A";

    if (filehash == SPRWinHookA.md5)
    {
      return SPRWinHookA.name;
    }

    Database::Malware SPRFakeSyscontrol;

    SPRFakeSyscontrol.md5 = "f9be49d2313f3e92b0f9f6a2b83029ea";
    SPRFakeSyscontrol.name = "SPR/Fake.Syscontrol";

    if (filehash == SPRFakeSyscontrol.md5)
    {
      return SPRFakeSyscontrol.name;
    }

    Database::Malware SPRFakeSpyWinRean;

    SPRFakeSpyWinRean.md5 = "4969ceb8fe6db5a5ee2e11969bf146bf";
    SPRFakeSpyWinRean.name = "SPR/Fake.SpyWinRean";

    if (filehash == SPRFakeSpyWinRean.md5)
    {
      return SPRFakeSpyWinRean.name;
    }

    Database::Malware SPRHoaxRenosEG4;

    SPRHoaxRenosEG4.md5 = "4b2a5bab4d14fe9d981bcff374279c28";
    SPRHoaxRenosEG4.name = "SPR/Hoax.Renos.EG.4";

    if (filehash == SPRHoaxRenosEG4.md5)
    {
      return SPRHoaxRenosEG4.name;
    }

    Database::Malware SPRSpamAgentG1;

    SPRSpamAgentG1.md5 = "801f1564f5ede2a8c72018916d00fd06";
    SPRSpamAgentG1.name = "SPR/Spam.Agent.G.1";

    if (filehash == SPRSpamAgentG1.md5)
    {
      return SPRSpamAgentG1.name;
    }

    Database::Malware TRRoguekdv644764;

    TRRoguekdv644764.md5 = "82ca15a8ec4b891e4ea920282a9e34f8";
    TRRoguekdv644764.name = "TR/Rogue.kdv.644764";

    if (filehash == TRRoguekdv644764.md5)
    {
      return TRRoguekdv644764.name;
    }

    Database::Malware TRRoguekdv638702;

    TRRoguekdv638702.md5 = "c1e7dc2ebd6f5e8ce82ec5c0fd845c7e";
    TRRoguekdv638702.name = "TR/Rogue.kdv.638702";

    if (filehash == TRRoguekdv638702.md5)
    {
      return TRRoguekdv638702.name;
    }


    Database::Malware TRObfuscateXY536;

    TRObfuscateXY536.md5 = "75791c664d816c00e78c408b810F22f7";
    TRObfuscateXY536.name = "TR/Obfuscate.XY.536";

    if (filehash == TRObfuscateXY536.md5)
    {
      return TRObfuscateXY536.name;
    }


    Database::Malware TRKazy47599;

    TRKazy47599.md5 = "231522ac73f23562d0d518171949d303";
    TRKazy47599.name = "TR/Kazy.47599";

    if (filehash == TRKazy47599.md5)
    {
      return TRKazy47599.name;
    }


    Database::Malware TRRoguekdv636707;

    TRRoguekdv636707.md5 = "9E4BB8C6AD26AD56B31624EC16DECEBB";
    TRRoguekdv636707.name = "TR/Rogue.kdv.636707";

    if (filehash == TRRoguekdv636707.md5)
    {
      return TRRoguekdv636707.name;
    }


    Database::Malware TRRoguekdv6367041;

    TRRoguekdv6367041.md5 = "7739b44903784e044025befedba141a7";
    TRRoguekdv6367041.name = "TR/Rogue.kdv.636704.1";

    if (filehash == TRRoguekdv6367041.md5)
    {
      return TRRoguekdv6367041.name;
    }



    Database::Malware TRSmallFI;

    TRSmallFI.md5 = "97054da52301ece758c26f5fe2682426";
    TRSmallFI.name = "TR/Small.FI";

    if (filehash == TRSmallFI.md5)
    {
      return TRSmallFI.name;
    }



    Database::Malware TRVBAgentaboe1;

    TRVBAgentaboe1.md5 = "0A9a10f0a4fbc82f22d78a252d685824";
    TRVBAgentaboe1.name = "TR/VB.Agent.aboe.1";

    if (filehash == TRVBAgentaboe1.md5)
    {
      return TRVBAgentaboe1.name;
    }



    Database::Malware TRDldrAgentgnpc1;

    TRDldrAgentgnpc1.md5 = "1628e8c79eb5622c59b0013199d41ade";
    TRDldrAgentgnpc1.name = "TR/Dldr.Agent.gnpc.1";

    if (filehash == TRDldrAgentgnpc1.md5)
    {
      return TRDldrAgentgnpc1.name;
    }

    Database::Malware TRFlamerA;

    TRFlamerA.md5 = "BDC9E04388BDA8527B398A8C34667E18";
    TRFlamerA.name = "TR/Flamer.A";

    if (filehash == TRFlamerA.md5)
    {
      return TRFlamerA.name;
    }

    Database::Malware TRSkelfA;

    TRSkelfA.md5 = "78EE9C318793ADB145A5ABDC07DB8F1B";
    TRSkelfA.name = "TR/Skelf.A";

    if (filehash == TRSkelfA.md5)
    {
      return TRSkelfA.name;
    }

    Database::Malware TRDldrZeagleA49;

    TRDldrZeagleA49.md5 = "1492c960c5895ec7ff20da88b2bdedc0";
    TRDldrZeagleA49.name = "TR/Dldr.Zeagle.A.49";

    if (filehash == TRDldrZeagleA49.md5)
    {
      return TRDldrZeagleA49.name;
    }


    Database::Malware TRKoobface11;

    TRKoobface11.md5 = "32b6d74310c5ba3ab9b219432c54e58b";
    TRKoobface11.name = "TR/Koobface.1.1";

    if (filehash == TRKoobface11.md5)
    {
      return TRKoobface11.name;
    }



    Database::Malware TRClaretoreA19;

    TRClaretoreA19.md5 = "5c37cff044ca6251fec1a3dd38a4e2dd";
    TRClaretoreA19.name = "TR/Claretore.A.19";

    if (filehash == TRClaretoreA19.md5)
    {
      return TRClaretoreA19.name;
    }



    Database::Malware TRSirefefAG35;

    TRSirefefAG35.md5 = "1bf005160D6c0469601128d75e8a0044";
    TRSirefefAG35.name = "TR/Sirefef.AG.35";

    if (filehash == TRSirefefAG35.md5)
    {
      return TRSirefefAG35.name;
    }



    Database::Malware TRCryptGypikonA9;

    TRCryptGypikonA9.md5 = "8950aecc4d90c7cc4c4b8e79b6a96260";
    TRCryptGypikonA9.name = "TR/Crypt.Gypikon.A.9";

    if (filehash == TRCryptGypikonA9.md5)
    {
      return TRCryptGypikonA9.name;
    }


    Database::Malware TRDropInjectoretcf;

    TRDropInjectoretcf.md5 = "dd8c3d5370438068e8ff61391d801e7b";
    TRDropInjectoretcf.name = "TR/Drop.Injector.etcf";

    if (filehash == TRDropInjectoretcf.md5)
    {
      return TRDropInjectoretcf.name;
    }


    Database::Malware TRInjectorLO;

    TRInjectorLO.md5 = "b2b0c8d66ef083810Bcf5f54e15ee806";
    TRInjectorLO.name = "TR/Injector.LO";

    if (filehash == TRInjectorLO.md5)
    {
      return TRInjectorLO.name;
    }


    Database::Malware TRMediyesEB1;

    TRMediyesEB1.md5 = "130ca53bb6f270a54cab5db7545b8c50";
    TRMediyesEB1.name = "TR/Mediyes.EB.1";

    if (filehash == TRMediyesEB1.md5)
    {
      return TRMediyesEB1.name;
    }


    Database::Malware TROffend70318871;

    TROffend70318871.md5 = "b437eda4eeba2a1a42c1943df177136d";
    TROffend70318871.name = "TR/Offend.7031887.1";

    if (filehash == TROffend70318871.md5)
    {
      return TROffend70318871.name;
    }



    Database::Malware TRKazyiwd;

    TRKazyiwd.md5 = "d542394dbb8f9e04a4be06476f3589c6";
    TRKazyiwd.name = "TR/Kazy.iwd";

    if (filehash == TRKazyiwd.md5)
    {
      return TRKazyiwd.name;
    }



    Database::Malware TRInjectorqmu;

    TRInjectorqmu.md5 = "3CCC73F049A1DE731BAF7EA8915C92A8";
    TRInjectorqmu.name = "TR/Injector.qmu";

    if (filehash == TRInjectorqmu.md5)
    {
      return TRInjectorqmu.name;
    }


    Database::Malware TRBuzusGN16;

    TRBuzusGN16.md5 = "CF972AC807B164BEA5E8DD06D6763B6C";
    TRBuzusGN16.name = "TR/Buzus.GN.16";

    if (filehash == TRBuzusGN16.md5)
    {
      return TRBuzusGN16.name;
    }


    Database::Malware TROffendKD506173;

    TROffendKD506173.md5 = "91df40067638c04187e53cc3aaab9719";
    TROffendKD506173.name = "TR/Offend.KD.506173";

    if (filehash == TROffendKD506173.md5)
    {
      return TROffendKD506173.name;
    }



    Database::Malware TRDldrVBaque;

    TRDldrVBaque.md5 = "6da6a8032a57b55e869c06363db0eb17";
    TRDldrVBaque.name = "TR/Dldr.VB.aque";

    if (filehash == TRDldrVBaque.md5)
    {
      return TRDldrVBaque.name;
    }


    Database::Malware TROffendkdv5809841;

    TROffendkdv5809841.md5 = "6786f1a6bbc8efdd73edcc440db6cbce";
    TROffendkdv5809841.name = "TR/Offend.kdv.580984.1";

    if (filehash == TROffendkdv5809841.md5)
    {
      return TROffendkdv5809841.name;
    }


    Database::Malware TRGraftor155813;

    TRGraftor155813.md5 = "cb89a6bc1962532c01b9e7f3a352391a";
    TRGraftor155813.name = "TR/Graftor.155813";

    if (filehash == TRGraftor155813.md5)
    {
      return TRGraftor155813.name;
    }


    Database::Malware TRSpyFarkoja;

    TRSpyFarkoja.md5 = "093ece008d3e41e9a7458c3928a4fb9b";
    TRSpyFarkoja.name = "TR/Spy.Farko.ja";

    if (filehash == TRSpyFarkoja.md5)
    {
      return TRSpyFarkoja.name;
    }


    Database::Malware TRRevetonA432;

    TRRevetonA432.md5 = "f91cc13a0D484e3b9ce1d244edb52035";
    TRRevetonA432.name = "TR/Reveton.A.432";

    if (filehash == TRRevetonA432.md5)
    {
      return TRRevetonA432.name;
    }


    Database::Malware TRSirefefBV2;

    TRSirefefBV2.md5 = "11028c6a84a967070cb1286550f2058f";
    TRSirefefBV2.name = "TR/Sirefef.BV.2";

    if (filehash == TRSirefefBV2.md5)
    {
      return TRSirefefBV2.name;
    }


    Database::Malware TRSirefefBP1;

    TRSirefefBP1.md5 = "b89cfbe8cb247b57d8c10Adaa66b462b";
    TRSirefefBP1.name = "TR/Sirefef.BP.1";

    if (filehash == TRSirefefBP1.md5)
    {
      return TRSirefefBP1.name;
    }


    Database::Malware TRRansomEJ3;

    TRRansomEJ3.md5 = "94f43752fa6302e206cb53fa4bfec20F";
    TRRansomEJ3.name = "TR/Ransom.EJ.3";

    if (filehash == TRRansomEJ3.md5)
    {
      return TRRansomEJ3.name;
    }


    Database::Malware TRDldrDarkmegiA;

    TRDldrDarkmegiA.md5 = "b3e7cab2ea9b8ee085214a9f52661297";
    TRDldrDarkmegiA.name = "TR/Dldr.Darkmegi.A";

    if (filehash == TRDldrDarkmegiA.md5)
    {
      return TRDldrDarkmegiA.name;
    }


    Database::Malware TRRevetonA153;

    TRRevetonA153.md5 = "056AB8CB1536D2282D77F828A6EDDFDE";
    TRRevetonA153.name = "TR/Reveton.A.153";

    if (filehash == TRRevetonA153.md5)
    {
      return TRRevetonA153.name;
    }


    Database::Malware TRRevetonA148;

    TRRevetonA148.md5 = "C0B070B314C7116975DDD9DB323F9B3C";
    TRRevetonA148.name = "TR/Reveton.A.148";

    if (filehash == TRRevetonA148.md5)
    {
      return TRRevetonA148.name;
    }


    Database::Malware TRLockScreenBO13;

    TRLockScreenBO13.md5 = "79615C5DC40F4F92E9BCEF07267B6D29";
    TRLockScreenBO13.name = "TR/LockScreen.BO.13";

    if (filehash == TRLockScreenBO13.md5)
    {
      return TRLockScreenBO13.name;
    }


    Database::Malware TRMalexE382;

    TRMalexE382.md5 = "66A022CA9613A9B2F0FB22D693064E97";
    TRMalexE382.name = "TR/Malex.E.382";

    if (filehash == TRMalexE382.md5)
    {
      return TRMalexE382.name;
    }


    Database::Malware TRSpam12;

    TRSpam12.md5 = "D6D66045C58DB10ED0A7C8E9E430A590";
    TRSpam12.name = "TR/Spam.1.2";

    if (filehash == TRSpam12.md5)
    {
      return TRSpam12.name;
    }


    Database::Malware TRRansomEJ56;

    TRRansomEJ56.md5 = "799259ADEA7A5B664DE93085A1BEE22A";
    TRRansomEJ56.name = "TR/Ransom.EJ.56";

    if (filehash == TRRansomEJ56.md5)
    {
      return TRRansomEJ56.name;
    }



    Database::Malware TRRansomEJ55;

    TRRansomEJ55.md5 = "48E38C1D8BD97F13BC0ACFAE45880ED3";
    TRRansomEJ55.name = "TR/Ransom.EJ.55";

    if (filehash == TRRansomEJ55.md5)
    {
      return TRRansomEJ55.name;
    }




    Database::Malware TRLebaglgk;

    TRLebaglgk.md5 = "91A6DC04EE087A42E9224DD152E6448F";
    TRLebaglgk.name = "TR/Lebag.lgk";

    if (filehash == TRLebaglgk.md5)
    {
      return TRLebaglgk.name;
    }




    Database::Malware TRRansomEJ65;

    TRRansomEJ65.md5 = "F718D3EAF4A59516E04B2594CDA186D5";
    TRRansomEJ65.name = "TR/Ransom.EJ.65";

    if (filehash == TRRansomEJ65.md5)
    {
      return TRRansomEJ65.name;
    }




    Database::Malware TRLebagktw;

    TRLebagktw.md5 = "D591660496D61021B32A8603B008B685";
    TRLebagktw.name = "TR/Lebag.ktw";

    if (filehash == TRLebagktw.md5)
    {
      return TRLebagktw.name;
    }


    Database::Malware TRSpyAgentOGS;

    TRSpyAgentOGS.md5 = "e22b6195d50b8f7c265542091628c218";
    TRSpyAgentOGS.name = "TR/Spy.Agent.OGS";

    if (filehash == TRSpyAgentOGS.md5)
    {
      return TRSpyAgentOGS.name;
    }



    Database::Malware TRSpyFarkoau;

    TRSpyFarkoau.md5 = "7d8488ae5125e9a1a893f50771d25d01";
    TRSpyFarkoau.name = "TR/Spy.Farko.au";

    if (filehash == TRSpyFarkoau.md5)
    {
      return TRSpyFarkoau.name;
    }



    Database::Malware TRFakeAVoke;

    TRFakeAVoke.md5 = "7a14060028698e2a2c5c64eb262c6868";
    TRFakeAVoke.name = "TR/FakeAV.oke";

    if (filehash == TRFakeAVoke.md5)
    {
      return TRFakeAVoke.name;
    }



    Database::Malware TRDldrMQL5MinerA;

    TRDldrMQL5MinerA.md5 = "1011e7a238d993f1151a49785b93a042";
    TRDldrMQL5MinerA.name = "TR/Dldr.MQL5Miner.A";

    if (filehash == TRDldrMQL5MinerA.md5)
    {
      return TRDldrMQL5MinerA.name;
    }


    Database::Malware TRTapaouxB2;

    TRTapaouxB2.md5 = "e2b5c47156508a31b74a1f48e814fbe7";
    TRTapaouxB2.name = "TR/Tapaoux.B.2";

    if (filehash == TRTapaouxB2.md5)
    {
      return TRTapaouxB2.name;
    }


    Database::Malware TRTapaouxB5;

    TRTapaouxB5.md5 = "3b4fed7138ebdc54d9cf6c7718088557";
    TRTapaouxB5.name = "TR/Tapaoux.B.5";

    if (filehash == TRTapaouxB5.md5)
    {
      return TRTapaouxB5.name;
    }


    Database::Malware TRDuquD2;

    TRDuquD2.md5 = "9E4FBEBCC458C9C29D3D2BC8272B5B32";
    TRDuquD2.name = "TR/Duqu.D.2";

    if (filehash == TRDuquD2.md5)
    {
      return TRDuquD2.name;
    }


    Database::Malware TRDuquD1;

    TRDuquD1.md5 = "eedca45bd613e0d9a9e5c69122007f17";
    TRDuquD1.name = "TR/Duqu.D.1";

    if (filehash == TRDuquD1.md5)
    {
      return TRDuquD1.name;
    }

    Database::Virus TRKazy30847;

TRKazy30847.md5 = "48E9FD1CD62455FC9539D95338589343";
TRKazy30847.name = "TR/Kazy.30847";

if (filehash == TRKazy30847.md5)
{

return TRKazy30847.name;

}


Database::Virus TRKazy319511;

TRKazy319511.md5 = "5C06EEE2D31F0E4AF6231B0D9E84806B";
TRKazy319511.name = "TR/Kazy.31951.1";

if (filehash == TRKazy319511.md5)
{

return TRKazy319511.name;

}

Database::Virus TRKazy308881;

TRKazy308881.md5 = "50558989A6D43317AE90383D72E7395F";
TRKazy308881.name = "TR/Kazy.30888.1";

if (filehash == TRKazy308881.md5)
{

return TRKazy308881.name;

}

Database::Virus TRKazy31315;

TRKazy31315.md5 = "677B74E7E99BE83915D17200FF1F97B0";
TRKazy31315.name = "TR/Kazy.31315";

if (filehash == TRKazy31315.md5)
{

return TRKazy31315.name;

}

Database::Virus TRKryptikOY;

TRKryptikOY.md5 = "234656F9F8D901A8AA32BB057BEA87FA";
TRKryptikOY.name = "TR/Kryptik.OY";

if (filehash == TRKryptikOY.md5)
{

return TRKryptikOY.name;

}

Database::Virus TRKazy31091;

TRKazy31091.md5 = "C84E0EBE9E175C9089758E05AC11F4CE";
TRKazy31091.name = "TR/Kazy.31091";

if (filehash == TRKazy31091.md5)
{

return TRKazy31091.name;

}

Database::Virus TRGendalkdv316739;

TRGendalkdv316739.md5 = "0BE55123C40A8F4AF0A355528551E306";
TRGendalkdv316739.name = "TR/Gendal.kdv.316739";

if (filehash == TRGendalkdv316739.md5)
{

return TRGendalkdv316739.name;

}

Database::Virus TRGendal6308516;

TRGendal6308516.md5 = "68A2AC9C6A085DD83B601FEEE7C29037";
TRGendal6308516.name = "TR/Gendal.6308516";

if (filehash == TRGendal6308516.md5)
{

return TRGendal6308516.name;

}

Database::Virus TRKazy150632;

TRKazy150632.md5 = "CAA13B954C5EE65AB5F6567F7AADE746";
TRKazy150632.name = "TR/Kazy.15063.2";

if (filehash == TRKazy150632.md5)
{

return TRKazy150632.name;

}

Database::Virus TRVBKryptegbx;

TRVBKryptegbx.md5 = "9D3FD5ECD989B6D056E1D94AD617217F";
TRVBKryptegbx.name = "TR/VBKrypt.egbx";

if (filehash == TRVBKryptegbx.md5)
{

return TRVBKryptegbx.name;

}

Database::Virus TRCycbot1;

TRCycbot1.md5 = "4D0B59243D9AC9D047A20858CAF74F52";
TRCycbot1.name = "TR/Cycbot.1";

if (filehash == TRCycbot1.md5)
{

return TRCycbot1.name;

}

Database::Virus TRKazy308475;

TRKazy308475.md5 = "BC84DE104E76468759C27EFA002F6FB9";
TRKazy308475.name = "TR/Kazy.30847.5";

if (filehash == TRKazy308475.md5)
{

return TRKazy308475.name;

}

Database::Virus TRGendal6393736;

TRGendal6393736.md5 = "431431D6F43798F3F250CAB863749C45";
TRGendal6393736.name = "TR/Gendal.6393736";

if (filehash == TRGendal6393736.md5)
{

return TRGendal6393736.name;

}

Database::Virus TRSpyRanbyusG19;

TRSpyRanbyusG19.md5 = "ED5E502DA77CE0A5F23DCD413DD78121";
TRSpyRanbyusG19.name = "TR/Spy.Ranbyus.G.19";

if (filehash == TRSpyRanbyusG19.md5)
{

return TRSpyRanbyusG19.name;

}

Database::Virus TRKazy308882;

TRKazy308882.md5 = "A8CE03B9BBE1E4B5E962A35B4B4777B5";
TRKazy308882.name = "TR/Kazy.30888.2";

if (filehash == TRKazy308882.md5)
{

return TRKazy308882.name;

}

Database::Virus TRMalagentA970;

TRMalagentA970.md5 = "6109DCAAD699F7ADD0B727106FC60642";
TRMalagentA970.name = "TR/Malagent.A.970";

if (filehash == TRMalagentA970.md5)
{

return TRMalagentA970.name;

}

Database::Virus TRVBInjectGQ14;

TRVBInjectGQ14.md5 = "22369A7A259F4D220BD6296613F8A165";
TRVBInjectGQ14.name = "TR/VB.Inject.GQ.14";

if (filehash == TRVBInjectGQ14.md5)
{

return TRVBInjectGQ14.name;

}

Database::Virus TRIrcbruteA892;

TRIrcbruteA892.md5 = "ED6132EF5093B25F19B530048F84A5D7";
TRIrcbruteA892.name = "TR/Ircbrute.A.892";

if (filehash == TRIrcbruteA892.md5)
{

return TRIrcbruteA892.name;

}

Database::Virus TRSpyDuquA;

TRSpyDuquA.md5 = "9749d38ae9b9ddd81b50aad679ee87ec";
TRSpyDuquA.name = "TR/Spy.Duqu.A";

if (filehash == TRSpyDuquA.md5)
{

return TRSpyDuquA.name;

}

Database::Virus TRDuquA1;

TRDuquA1.md5 = "4541e850a228eb69fd0f0e924624b245";
TRDuquA1.name = "TR/Duqu.A.1";

if (filehash == TRDuquA1.md5)
{

return TRDuquA1.name;

}

Database::Virus TRInjector1269769;

TRInjector1269769.md5 = "6409AA13D8C4EEA0845F6CF912C570EB";
TRInjector1269769.name = "TR/Injector.126976.9";

if (filehash == TRInjector1269769.md5)
{

return TRInjector1269769.name;

}

Database::Virus TRFakeRean1624;

TRFakeRean1624.md5 = "307C71D9E6B99F3DD6ACBC21D973B281";
TRFakeRean1624.name = "TR/Fake.Rean.1624";

if (filehash == TRFakeRean1624.md5)
{

return TRFakeRean1624.name;

}

Database::Virus TRYakessf;

TRYakessf.md5 = "F046D7F182DCA08D6DE0306EADF1DAAC";
TRYakessf.name = "TR/Yakes.sf";

if (filehash == TRYakessf.md5)
{

return TRYakessf.name;

}

Database::Virus TRSpy90112737;

TRSpy90112737.md5 = "84546B3BD70270C6C3C76B53D947839C";
TRSpy90112737.name = "TR/Spy.90112.737";

if (filehash == TRSpy90112737.md5)
{

return TRSpy90112737.name;

}

Database::Virus TRInjectorKSK;

TRInjectorKSK.md5 = "440647BEBF95EC9E5E82C77E166E2DED";
TRInjectorKSK.name = "TR/Injector.KSK";

if (filehash == TRInjectorKSK.md5)
{

return TRInjectorKSK.name;

}

Database::Virus TRJorikIRCbotadl;

TRJorikIRCbotadl.md5 = "20A18A01433D43128149E404226AE524";
TRJorikIRCbotadl.name = "TR/Jorik.IRCbot.adl";

if (filehash == TRJorikIRCbotadl.md5)
{

return TRJorikIRCbotadl.name;

}

Database::Virus TRDelfsnifA2;

TRDelfsnifA2.md5 = "DF7BC7447218621DC038D00A8E2196B9";
TRDelfsnifA2.name = "TR/Delfsnif.A.2";

if (filehash == TRDelfsnifA2.md5)
{

return TRDelfsnifA2.name;

}

Database::Virus TRPSWOnlineGamesKDGP;

TRPSWOnlineGamesKDGP.md5 = "2CF79A2A358B055CA11910D9D54E9A73";
TRPSWOnlineGamesKDGP.name = "TR/PSW.OnlineGames.KDGP";

if (filehash == TRPSWOnlineGamesKDGP.md5)
{

return TRPSWOnlineGamesKDGP.name;

}

Database::Virus TRSmallZZT;

TRSmallZZT.md5 = "ACC4AC878D2B8D267A34CCB2DE4DA60F";
TRSmallZZT.name = "TR/Small.ZZT";

if (filehash == TRSmallZZT.md5)
{

return TRSmallZZT.name;

}

Database::Virus TRFakealertAN88;

TRFakealertAN88.md5 = "B2E93E6DEFBC258F7299A27962FA9BA3";
TRFakealertAN88.name = "TR/Fakealert.AN.88";

if (filehash == TRFakealertAN88.md5)
{

return TRFakealertAN88.name;

}

Database::Virus TRRimecudA21;

TRRimecudA21.md5 = "2C779E7395E100EDE9756FE9DD2821DE";
TRRimecudA21.name = "TR/Rimecud.A.21";

if (filehash == TRRimecudA21.md5)
{

return TRRimecudA21.name;

}

Database::Virus TRSpyAntiavA;

TRSpyAntiavA.md5 = "2D9C1FE209591B57E00B437D678E658A";
TRSpyAntiavA.name = "TR/Spy.Antiav.A";

if (filehash == TRSpyAntiavA.md5)
{

return TRSpyAntiavA.name;

}

Database::Virus TRSpy48998428;

TRSpy48998428.md5 = "1F702D8C4A75439B30C2CB5FD9B4447C";
TRSpy48998428.name = "TR/Spy.489984.28";

if (filehash == TRSpy48998428.md5)
{

return TRSpy48998428.name;

}

Database::Virus TRDropAgoop;

TRDropAgoop.md5 = "B0E217D45E884ADAA41B0D0265AE666C";
TRDropAgoop.name = "TR/Drop.Ag.oop";

if (filehash == TRDropAgoop.md5)
{

return TRDropAgoop.name;

}

Database::Virus TRDromevA;

TRDromevA.md5 = "E355D9224C72A641B49645B73B076FE6";
TRDromevA.name = "TR/Dromev.A";

if (filehash == TRDromevA.md5)
{

return TRDromevA.name;

}

Database::Virus TRAgent69632;

TRAgent69632.md5 = "F3AC620DEF76EC88C7637433ABF1D980";
TRAgent69632.name = "TR/Agent.69632";

if (filehash == TRAgent69632.md5)
{

return TRAgent69632.name;

}

Database::Virus TRVBKryptecgf1;

TRVBKryptecgf1.md5 = "070B47D909B37F34E39EEE2915520D8D";
TRVBKryptecgf1.name = "TR/VBKrypt.ecgf.1";

if (filehash == TRVBKryptecgf1.md5)
{

return TRVBKryptecgf1.name;

}

Database::Virus TRFakealertqma;

TRFakealertqma.md5 = "C9B684BDEB0D836BDDBBEB74142EE5D6";
TRFakealertqma.name = "TR/Fakealert.qma";

if (filehash == TRFakealertqma.md5)
{

return TRFakealertqma.name;

}

Database::Virus TRBuzusEY3;

TRBuzusEY3.md5 = "C67B6F1221C241280833CAB483D631CB";
TRBuzusEY3.name = "TR/Buzus.EY.3";

if (filehash == TRBuzusEY3.md5)
{

return TRBuzusEY3.name;

}

Database::Virus TRAlgaloebB;

TRAlgaloebB.md5 = "35E7CC3B15B8504E7FA7EBF07A4F45B5";
TRAlgaloebB.name = "TR/Algaloeb.B";

if (filehash == TRAlgaloebB.md5)
{

return TRAlgaloebB.name;

}

Database::Virus TRDipleruv;

TRDipleruv.md5 = "E73187B0753D854A5C7DBBA340FAA477";
TRDipleruv.name = "TR/Diple.ruv";

if (filehash == TRDipleruv.md5)
{

return TRDipleruv.name;

}

Database::Virus TRBuzusEC41;

TRBuzusEC41.md5 = "132A989554F5E69C4E6A13D632B4F9B8";
TRBuzusEC41.name = "TR/Buzus.EC.41";

if (filehash == TRBuzusEC41.md5)
{

return TRBuzusEC41.name;

}

Database::Virus TRGruenFink5;

TRGruenFink5.md5 = "309ede406988486bf81e603c514b4b82";
TRGruenFink5.name = "TR/GruenFink.5";

if (filehash == TRGruenFink5.md5)
{

return TRGruenFink5.name;

}

Database::Virus TRIrcbruteA857;

TRIrcbruteA857.md5 = "104DE28DD07BD41A163A922C7EC23E8E";
TRIrcbruteA857.name = "TR/Ircbrute.A.857";

if (filehash == TRIrcbruteA857.md5)
{

return TRIrcbruteA857.name;

}

Database::Virus TRRimecudA22;

TRRimecudA22.md5 = "486F73E377CADCB12A607018486D8CD8";
TRRimecudA22.name = "TR/Rimecud.A.22";

if (filehash == TRRimecudA22.md5)
{

return TRRimecudA22.name;

}

Database::Virus TRRansomWinLockA;

TRRansomWinLockA.md5 = "B9CF011968971CDD8424BC463603B71D";
TRRansomWinLockA.name = "TR/Ransom.WinLock.A";

if (filehash == TRRansomWinLockA.md5)
{

return TRRansomWinLockA.name;

}

Database::Virus TRSpyRanbyusG21;

TRSpyRanbyusG21.md5 = "ACAA94834FBE495D7EE75FA02033ED6C";
TRSpyRanbyusG21.name = "TR/Spy.Ranbyus.G.21";

if (filehash == TRSpyRanbyusG21.md5)
{

return TRSpyRanbyusG21.name;

}

Database::Virus TRFakeAVanm;

TRFakeAVanm.md5 = "88F32B47676BEA874374EE2CDDF5EE5A";
TRFakeAVanm.name = "TR/FakeAV.anm";

if (filehash == TRFakeAVanm.md5)
{

return TRFakeAVanm.name;

}

Database::Virus TRFakeSysdef506;

TRFakeSysdef506.md5 = "15b0ea0b285381d3fe15d796d557e6dd";
TRFakeSysdef506.name = "TR/FakeSysdef.506";

if (filehash == TRFakeSysdef506.md5)
{

return TRFakeSysdef506.name;

}

Database::Virus TRScardrdl;

TRScardrdl.md5 = "FFAB90D9FF8A94092B0C8B3242EFCAA8";
TRScardrdl.name = "TR/Scar.drdl";

if (filehash == TRScardrdl.md5)
{

return TRScardrdl.name;

}

Database::Virus TRIrcbruteA845;

TRIrcbruteA845.md5 = "28B4FCD30ED6C315666A78052226017D";
TRIrcbruteA845.name = "TR/Ircbrute.A.845";

if (filehash == TRIrcbruteA845.md5)
{

return TRIrcbruteA845.name;

}

Database::Virus TRAgentpsait;

TRAgentpsait.md5 = "3C4E8D106C02EEEB3E9FBE74B57F1B94";
TRAgentpsait.name = "TR/Agent.psait";

if (filehash == TRAgentpsait.md5)
{

return TRAgentpsait.name;

}

Database::Virus TRVBAHB1;

TRVBAHB1.md5 = "FEF26399FD6188C653C8CB6A91FBE5C0";
TRVBAHB1.name = "TR/VB.AHB.1";

if (filehash == TRVBAHB1.md5)
{

return TRVBAHB1.name;

}

Database::Virus TRPincavbjcw1;

TRPincavbjcw1.md5 = "FB8C61760B9AA4DEE0453158F073F48F";
TRPincavbjcw1.name = "TR/Pincav.bjcw.1";

if (filehash == TRPincavbjcw1.md5)
{

return TRPincavbjcw1.name;

}

Database::Virus TRSpy36044839;

TRSpy36044839.md5 = "AA26C7D58FED026E915E4B3BD3C43D94";
TRSpy36044839.name = "TR/Spy.360448.39";

if (filehash == TRSpy36044839.md5)
{

return TRSpy36044839.name;

}

Database::Virus TRAlgaloebA;

TRAlgaloebA.md5 = "DE50C0444263F1B4E041E7C5F40C18AE";
TRAlgaloebA.name = "TR/Algaloeb.A";

if (filehash == TRAlgaloebA.md5)
{

return TRAlgaloebA.name;

}

Database::Virus TRSpy20838416;

TRSpy20838416.md5 = "4C343C9FCECE2E6739A5834579448A46";
TRSpy20838416.name = "TR/Spy.208384.16";

if (filehash == TRSpy20838416.md5)
{

return TRSpy20838416.name;

}

Database::Virus TRIrcbruteA1130;

TRIrcbruteA1130.md5 = "33A0F48ADF1A5C58537F7E6979D4F930";
TRIrcbruteA1130.name = "TR/Ircbrute.A.1130";

if (filehash == TRIrcbruteA1130.md5)
{

return TRIrcbruteA1130.name;

}

Database::Virus TRSpy7577632;

TRSpy7577632.md5 = "E169A143BE66E65FD96F8125BC116BDE";
TRSpy7577632.name = "TR/Spy.75776.32";

if (filehash == TRSpy7577632.md5)
{

return TRSpy7577632.name;

}

Database::Virus TRRimodA255;

TRRimodA255.md5 = "3C244D2FA504E645C4C71139A6146425";
TRRimodA255.name = "TR/Rimod.A.255";

if (filehash == TRRimodA255.md5)
{

return TRRimodA255.name;

}

Database::Virus TRAgentA144384;

TRAgentA144384.md5 = "390A20C383A40EC5318FB19C51E6F889";
TRAgentA144384.name = "TR/Agent.A.144384";

if (filehash == TRAgentA144384.md5)
{

return TRAgentA144384.name;

}

Database::Virus TRAgent286049;

TRAgent286049.md5 = "07FB56F72F4F50D93B7886D853B9C31D";
TRAgent286049.name = "TR/Agent.286049";

if (filehash == TRAgent286049.md5)
{

return TRAgent286049.name;

}

Database::Virus TRVBInjectGM34;

TRVBInjectGM34.md5 = "57D608B6363C5DF81956AB2980AA6B8D";
TRVBInjectGM34.name = "TR/VB.Inject.GM.34";

if (filehash == TRVBInjectGM34.md5)
{

return TRVBInjectGM34.name;

}

Database::Virus TRScarehcu12;

TRScarehcu12.md5 = "3FEDC8C9E4618D998371349723D1BC41";
TRScarehcu12.name = "TR/Scar.ehcu.12";

if (filehash == TRScarehcu12.md5)
{

return TRScarehcu12.name;

}

Database::Virus TRFakeAV138;

TRFakeAV138.md5 = "27D7154A5CC03652101F6DD874FE792C";
TRFakeAV138.name = "TR/FakeAV.13.8";

if (filehash == TRFakeAV138.md5)
{

return TRFakeAV138.name;

}

Database::Virus TRAgent225280;

TRAgent225280.md5 = "B4849B27DAB466487C460D2DC1A9FC37";
TRAgent225280.name = "TR/Agent.225280";

if (filehash == TRAgent225280.md5)
{

return TRAgent225280.name;

}

Database::Virus TRBuzusEY2;

TRBuzusEY2.md5 = "7BE4701F62ED2330290DA1063481BFDF";
TRBuzusEY2.name = "TR/Buzus.EY.2";

if (filehash == TRBuzusEY2.md5)
{

return TRBuzusEY2.name;

}

Database::Virus TRObfuscateBX116;

TRObfuscateBX116.md5 = "AD95F16360591B4A493BAB90B9DE921B";
TRObfuscateBX116.name = "TR/Obfuscate.BX.116";

if (filehash == TRObfuscateBX116.md5)
{

return TRObfuscateBX116.name;

}

Database::Virus TRKazy248898;

TRKazy248898.md5 = "3DF294ECF896B767C9F03CF2149E2A75";
TRKazy248898.name = "TR/Kazy.24889.8";

if (filehash == TRKazy248898.md5)
{

return TRKazy248898.name;

}

Database::Virus TRKazy313202;

TRKazy313202.md5 = "34C572F2B6670E332B8DAAD52AC9A0C2";
TRKazy313202.name = "TR/Kazy.31320.2";

if (filehash == TRKazy313202.md5)
{

return TRKazy313202.name;

}

Database::Virus TRLodapA14;

TRLodapA14.md5 = "D59F4FCD627EA26DEB7D3240831FF862";
TRLodapA14.name = "TR/Lodap.A.14";

if (filehash == TRLodapA14.md5)
{

return TRLodapA14.name;

}

Database::Virus TRYakesajw;

TRYakesajw.md5 = "84912A4480E54ACC70D33084BA9C3A99";
TRYakesajw.name = "TR/Yakes.ajw";

if (filehash == TRYakesajw.md5)
{

return TRYakesajw.name;

}

Database::Virus TRIrcbruteA889;

TRIrcbruteA889.md5 = "F01F67FE0C9DAE8A8973D8209FA1DB1A";
TRIrcbruteA889.name = "TR/Ircbrute.A.889";

if (filehash == TRIrcbruteA889.md5)
{

return TRIrcbruteA889.name;

}

Database::Virus TRDropStreabA;

TRDropStreabA.md5 = "16F019DE3267A5A5B4D56407765921FB";
TRDropStreabA.name = "TR/Drop.Streab.A";

if (filehash == TRDropStreabA.md5)
{

return TRDropStreabA.name;

}

Database::Virus TRIrcbruteA791;

TRIrcbruteA791.md5 = "A98DC68388D2199E85078AA3D4A58AC9";
TRIrcbruteA791.name = "TR/Ircbrute.A.791";

if (filehash == TRIrcbruteA791.md5)
{

return TRIrcbruteA791.name;

}

Database::Virus TRRimecudA20;

TRRimecudA20.md5 = "7A3B050DAB93E56852FCBD98F82C03DF";
TRRimecudA20.name = "TR/Rimecud.A.20";

if (filehash == TRRimecudA20.md5)
{

return TRRimecudA20.name;

}

Database::Virus TRVBaha1;

TRVBaha1.md5 = "26799179FAA5FFEB74AAD484DE3F2A3C";
TRVBaha1.name = "TR/VB.aha.1";

if (filehash == TRVBaha1.md5)
{

return TRVBaha1.name;

}

Database::Virus TRBuzusBB17;

TRBuzusBB17.md5 = "A79CAD593C97B7BD4764C6E9C4D51B5F";
TRBuzusBB17.name = "TR/Buzus.BB.17";

if (filehash == TRBuzusBB17.md5)
{

return TRBuzusBB17.name;

}

Database::Virus TRIrcbruteA855;

TRIrcbruteA855.md5 = "7BD90F47569E40747954E7F53C2BAE5A";
TRIrcbruteA855.name = "TR/Ircbrute.A.855";

if (filehash == TRIrcbruteA855.md5)
{

return TRIrcbruteA855.name;

}

Database::Virus TRVBKryptdjnz;

TRVBKryptdjnz.md5 = "5721F754F350A66DF20C9761F79309EC";
TRVBKryptdjnz.name = "TR/VBKrypt.djnz";

if (filehash == TRVBKryptdjnz.md5)
{

return TRVBKryptdjnz.name;

}

Database::Virus TRVBInjectGP61;

TRVBInjectGP61.md5 = "495BAA02D14599EB61524D6C6A1DB936";
TRVBInjectGP61.name = "TR/VB.Inject.GP.61";

if (filehash == TRVBInjectGP61.md5)
{

return TRVBInjectGP61.name;

}

Database::Virus TRSpySpyEyeHH;

TRSpySpyEyeHH.md5 = "0222a57e64b2f3fe7463a530c256c4ef";
TRSpySpyEyeHH.name = "TR/Spy.SpyEye.HH";

if (filehash == TRSpySpyEyeHH.md5)
{

return TRSpySpyEyeHH.name;

}

Database::Virus TRSpy163840371;

TRSpy163840371.md5 = "541fd503d9cde8cf750cb6fceb6610be";
TRSpy163840371.name = "TR/Spy.163840.371";

if (filehash == TRSpy163840371.md5)
{

return TRSpy163840371.name;

}

Database::Virus TRGendalKD355986;

TRGendalKD355986.md5 = "9e710d2b873dfa0e81fb38550dbc3775";
TRGendalKD355986.name = "TR/Gendal.KD.355986";

if (filehash == TRGendalKD355986.md5)
{

return TRGendalKD355986.name;

}

Database::Virus TRDropSirefefB746;

TRDropSirefefB746.md5 = "df99272c578ca11d343058ef587da81c";
TRDropSirefefB746.name = "TR/Drop.Sirefef.B.746";

if (filehash == TRDropSirefefB746.md5)
{

return TRDropSirefefB746.name;

}


Database::Virus TRDropSirefefB688;

TRDropSirefefB688.md5 = "08d5f38258e31cd5e3594ca5ca2e6599";
TRDropSirefefB688.name = "TR/Drop.Sirefef.B.688";

if (filehash == TRDropSirefefB688.md5)
{

return TRDropSirefefB688.name;

}


Database::Virus TRDropInjectoraws;

TRDropInjectoraws.md5 = "4A45CF79C79BF91655597D0D77D11A70";
TRDropInjectoraws.name = "TR/Drop.Injector.aws";

if (filehash == TRDropInjectoraws.md5)
{

return TRDropInjectoraws.name;

}


Database::Virus TRAlureonA195;

TRAlureonA195.md5 = "A443833EB7099D10081702459F5EAD47";
TRAlureonA195.name = "TR/Alureon.A.195";

if (filehash == TRAlureonA195.md5)
{

return TRAlureonA195.name;

}

Database::Virus TRVBKryptAC;

TRVBKryptAC.md5 = "4542B638A531B84EEFDBB6A2EC91D593";
TRVBKryptAC.name = "TR/VBKrypt.AC";

if (filehash == TRVBKryptAC.md5)
{

return TRVBKryptAC.name;

}

Database::Virus TRVBago1;

TRVBago1.md5 = "656780217F9B58FCFD8890A53E874109";
TRVBago1.name = "TR/VB.ago.1";

if (filehash == TRVBago1.md5)
{

return TRVBago1.name;

}

Database::Virus TRTrafogA513;

TRTrafogA513.md5 = "9EEC40F1469B8CBF7B1EF3EAAE616218";
TRTrafogA513.name = "TR/Trafog.A.513";

if (filehash == TRTrafogA513.md5)
{

return TRTrafogA513.name;

}

Database::Virus TRMSILCryptFO;

TRMSILCryptFO.md5 = "BAE283DC1C8A76CBEEA644A0B7CD6EFB";
TRMSILCryptFO.name = "TR/MSIL.Crypt.FO";

if (filehash == TRMSILCryptFO.md5)
{

return TRMSILCryptFO.name;

}

Database::Virus TRInjectorGB;

TRInjectorGB.md5 = "8C84F0FB876401D8CBA48961FE50A65F";
TRInjectorGB.name = "TR/Injector.GB";

if (filehash == TRInjectorGB.md5)
{

return TRInjectorGB.name;

}


Database::Virus TRMSILCryptfn;

TRMSILCryptfn.md5 = "A65D9C0CCADB91983EF545D00334B5A2";
TRMSILCryptfn.name = "TR/MSIL.Crypt.fn";

if (filehash == TRMSILCryptfn.md5)
{

return TRMSILCryptfn.name;

}

Database::Virus TRMalagentA1112;

TRMalagentA1112.md5 = "8D3FC62821C436169249EA5E09C53C5D";
TRMalagentA1112.name = "TR/Malagent.A.1112";

if (filehash == TRMalagentA1112.md5)
{

return TRMalagentA1112.name;

}

Database::Virus TRLethicF;

TRLethicF.md5 = "1276E180757A47BA13EA52EBB0FBCABE";
TRLethicF.name = "TR/Lethic.F";

if (filehash == TRLethicF.md5)
{

return TRLethicF.name;

}

Database::Virus TRGendalkdv273400;

TRGendalkdv273400.md5 = "D1F009C926E9D341E6B565D6BC443526";
TRGendalkdv273400.name = "TR/Gendal.kdv.273400";

if (filehash == TRGendalkdv273400.md5)
{

return TRGendalkdv273400.name;

}

Database::Virus TRGendalkdv257340;

TRGendalkdv257340.md5 = "9EC5FBCC0283608D0D5A9F4FD078BB99";
TRGendalkdv257340.name = "TR/Gendal.kdv.257340";

if (filehash == TRGendalkdv257340.md5)
{

return TRGendalkdv257340.name;

}

Database::Virus TRObfuscateBX108;

TRObfuscateBX108.md5 = "2847D66ADCBE7398C6920DDF2A6271A3";
TRObfuscateBX108.name = "TR/Obfuscate.BX.108";

if (filehash == TRObfuscateBX108.md5)
{

return TRObfuscateBX108.name;

}

Database::Virus TRKazy23507;

TRKazy23507.md5 = "a206760f21511e2907cc6cc31f146cf7";
TRKazy23507.name = "TR/Kazy.23507";

if (filehash == TRKazy23507.md5)
{

return TRKazy23507.name;

}

Database::Virus TRWinlockBT;

TRWinlockBT.md5 = "4267C365F92CD9C8E0524AF98D85CBEF";
TRWinlockBT.name = "TR/Winlock.BT";

if (filehash == TRWinlockBT.md5)
{

return TRWinlockBT.name;

}

Database::Virus TRObfuscateBX95;

TRObfuscateBX95.md5 = "153A2C388EFA991F174AE560D4E1D9B8";
TRObfuscateBX95.name = "TR/Obfuscate.BX.95";

if (filehash == TRObfuscateBX95.md5)
{

return TRObfuscateBX95.name;

}

Database::Virus TRObfuscateBX125;

TRObfuscateBX125.md5 = "042D00FF263C59D8F0C82CE719C87806";
TRObfuscateBX125.name = "TR/Obfuscate.BX.125";

if (filehash == TRObfuscateBX125.md5)
{

return TRObfuscateBX125.name;

}

Database::Virus TRObfuscateBX115;

TRObfuscateBX115.md5 = "9E193A98E59FE3E9939FD288821959A3";
TRObfuscateBX115.name = "TR/Obfuscate.BX.115";

if (filehash == TRObfuscateBX115.md5)
{

return TRObfuscateBX115.name;

}

Database::Virus TRObfuscateBX113;

TRObfuscateBX113.md5 = "9D02FFEC2E96A652C5388E9251BD609B";
TRObfuscateBX113.name = "TR/Obfuscate.BX.113";

if (filehash == TRObfuscateBX113.md5)
{

return TRObfuscateBX113.name;

}

Database::Virus TRObfuscateBX112;

TRObfuscateBX112.md5 = "5DB63091B5D3C0F18819F6D14C0E5598";
TRObfuscateBX112.name = "TR/Obfuscate.BX.112";

if (filehash == TRObfuscateBX112.md5)
{

return TRObfuscateBX112.name;

}

Database::Virus TRJorikIRCbotagl1;

TRJorikIRCbotagl1.md5 = "88C054DEBA0271E5C9238EB28DE6E024";
TRJorikIRCbotagl1.name = "TR/Jorik.IRCbot.agl.1";

if (filehash == TRJorikIRCbotagl1.md5)
{

return TRJorikIRCbotagl1.name;

}

Database::Virus TRIrcbruteA564;

TRIrcbruteA564.md5 = "79B6597F87059A3AA0931CDEE2A8304E";
TRIrcbruteA564.name = "TR/Ircbrute.A.564";

if (filehash == TRIrcbruteA564.md5)
{

return TRIrcbruteA564.name;

}

Database::Virus TRIrcbruteA1299;

TRIrcbruteA1299.md5 = "63678003E0583A3A29824086FE3A439F";
TRIrcbruteA1299.name = "TR/Ircbrute.A.1299";

if (filehash == TRIrcbruteA1299.md5)
{

return TRIrcbruteA1299.name;

}

Database::Virus TRIrcbruteA1298;

TRIrcbruteA1298.md5 = "A43E66250755BC62951B6DAEFA2C6388";
TRIrcbruteA1298.name = "TR/Ircbrute.A.1298";

if (filehash == TRIrcbruteA1298.md5)
{

return TRIrcbruteA1298.name;

}

Database::Virus TRIrcbruteA1297;

TRIrcbruteA1297.md5 = "AD2ED8807225601258B4D83E83935F74";
TRIrcbruteA1297.name = "TR/Ircbrute.A.1297";

if (filehash == TRIrcbruteA1297.md5)
{

return TRIrcbruteA1297.name;

}

Database::Virus TRIrcbruteA1295;

TRIrcbruteA1295.md5 = "6756D86D32FA9D9467737B1A9B60ED83";
TRIrcbruteA1295.name = "TR/Ircbrute.A.1295";

if (filehash == TRIrcbruteA1295.md5)
{

return TRIrcbruteA1295.name;

}

Database::Virus TRIrcbruteA1292;

TRIrcbruteA1292.md5 = "1E8E7CDD02E6EAA9103192A25CA094A1";
TRIrcbruteA1292.name = "TR/Ircbrute.A.1292";

if (filehash == TRIrcbruteA1292.md5)
{

return TRIrcbruteA1292.name;

}

Database::Virus TRIrcbruteA1296;

TRIrcbruteA1296.md5 = "BA46F2F1A72956A4A4141926114CF706";
TRIrcbruteA1296.name = "TR/Ircbrute.A.1296";

if (filehash == TRIrcbruteA1296.md5)
{

return TRIrcbruteA1296.name;

}

Database::Virus TRIrcbruteA1291;

TRIrcbruteA1291.md5 = "74CAB58E7647BACC4E6C59B03C14C9A4";
TRIrcbruteA1291.name = "TR/Ircbrute.A.1291";

if (filehash == TRIrcbruteA1291.md5)
{

return TRIrcbruteA1291.name;

}


Database::Virus TRFakeSysdefA873;

TRFakeSysdefA873.md5 = "5AA0177803695290BCA22BCE79802845";
TRFakeSysdefA873.name = "TR/FakeSysdef.A.873";

if (filehash == TRFakeSysdefA873.md5)
{

return TRFakeSysdefA873.name;

}

Database::Virus TRFakeSysdefA868;

TRFakeSysdefA868.md5 = "20DE5ECFBD8CEB32A0AB42F124B651EC";
TRFakeSysdefA868.name = "TR/FakeSysdef.A.868";

if (filehash == TRFakeSysdefA868.md5)
{

return TRFakeSysdefA868.name;

}

Database::Virus TRFakeSysdefA866;

TRFakeSysdefA866.md5 = "C5CE8AFBAF33ED3AE89AE8138992DC24";
TRFakeSysdefA866.name = "TR/FakeSysdef.A.866";

if (filehash == TRFakeSysdefA866.md5)
{

return TRFakeSysdefA866.name;

}

Database::Virus TRKazy331776;

TRKazy331776.md5 = "25601D8D71A9C410F6C29AF2BF8DD027";
TRKazy331776.name = "TR/Kazy.331776";

if (filehash == TRKazy331776.md5)
{

return TRKazy331776.name;

}

Database::Virus TRFakeAVaih;

TRFakeAVaih.md5 = "87F23605E46E40C467027790DDA23E65";
TRFakeAVaih.name = "TR/FakeAV.aih";

if (filehash == TRFakeAVaih.md5)
{

return TRFakeAVaih.name;

}

Database::Virus TRFakeRean491;

TRFakeRean491.md5 = "44DD9283FF74F64ACFB5D3D5AED10FE9";
TRFakeRean491.name = "TR/Fake.Rean.491";

if (filehash == TRFakeRean491.md5)
{

return TRFakeRean491.name;

}

Database::Virus TRRimecudA262;

TRRimecudA262.md5 = "7BB2418802B9B2F4612AF18885B000E2";
TRRimecudA262.name = "TR/Rimecud.A.262";

if (filehash == TRRimecudA262.md5)
{

return TRRimecudA262.name;

}

Database::Virus TRRimecudA260;

TRRimecudA260.md5 = "B09A1033DEAFC0A94CAB634708AD88CC";
TRRimecudA260.name = "TR/Rimecud.A.260";

if (filehash == TRRimecudA260.md5)
{

return TRRimecudA260.name;

}

Database::Virus TRRimecudA263;

TRRimecudA263.md5 = "3D0ED395E3CFAABDFDCE1406CE0A399E";
TRRimecudA263.name = "TR/Rimecud.A.263";

if (filehash == TRRimecudA263.md5)
{

return TRRimecudA263.name;

}

Database::Virus TRRimecudA261;

TRRimecudA261.md5 = "E33EFFA68256CD6C959092CFF3956D04";
TRRimecudA261.name = "TR/Rimecud.A.261";

if (filehash == TRRimecudA261.md5)
{

return TRRimecudA261.name;

}

Database::Virus TRRimecudA259;

TRRimecudA259.md5 = "2BC3153160467FE8BEDDF5D925983F1A";
TRRimecudA259.name = "TR/Rimecud.A.259";

if (filehash == TRRimecudA259.md5)
{

return TRRimecudA259.name;

}

Database::Virus TRRimecudA257;

TRRimecudA257.md5 = "D6E57C12EBBCD8CC387D131BA5542ECA";
TRRimecudA257.name = "TR/Rimecud.A.257";

if (filehash == TRRimecudA257.md5)
{

return TRRimecudA257.name;

}

Database::Virus TRRimecudA256;

TRRimecudA256.md5 = "140181A56BAB0B2D68D1476EF310B51F";
TRRimecudA256.name = "TR/Rimecud.A.256";

if (filehash == TRRimecudA256.md5)
{

return TRRimecudA256.name;

}

Database::Virus TRRimecudA255;

TRRimecudA255.md5 = "E5BDD822BF2CF5E9D2CC09C9ADCEA145";
TRRimecudA255.name = "TR/Rimecud.A.255";

if (filehash == TRRimecudA255.md5)
{

return TRRimecudA255.name;

}

Database::Virus TRRimecudA254;

TRRimecudA254.md5 = "81619DE3A99DE130BD4E9FA30146836E";
TRRimecudA254.name = "TR/Rimecud.A.254";

if (filehash == TRRimecudA254.md5)
{

return TRRimecudA254.name;

}

Database::Virus TRFakeRean479;

TRFakeRean479.md5 = "E18531567316D37BA463F983FC126871";
TRFakeRean479.name = "TR/Fake.Rean.479";

if (filehash == TRFakeRean479.md5)
{

return TRFakeRean479.name;

}

Database::Virus TRFakeRean305;

TRFakeRean305.md5 = "94F526B3A5D142417B23DAA9BED86CBC";
TRFakeRean305.name = "TR/Fake.Rean.305";

if (filehash == TRFakeRean305.md5)
{

return TRFakeRean305.name;

}

Database::Virus TRFakeRean2005;

TRFakeRean2005.md5 = "6C8F4A2E79196801A44E3A3FE0A82EB3";
TRFakeRean2005.name = "TR/Fake.Rean.2005";

if (filehash == TRFakeRean2005.md5)
{

return TRFakeRean2005.name;

}

Database::Virus TRFakeRean2004;

TRFakeRean2004.md5 = "EDD049D4CF8EC454A2F858D8429A7F18";
TRFakeRean2004.name = "TR/Fake.Rean.2004";

if (filehash == TRFakeRean2004.md5)
{

return TRFakeRean2004.name;

}

Database::Virus TRFakeRean2003;

TRFakeRean2003.md5 = "940EEB13A72101CC2A67D2E5E603702F";
TRFakeRean2003.name = "TR/Fake.Rean.2003";

if (filehash == TRFakeRean2003.md5)
{

return TRFakeRean2003.name;

}

Database::Virus TRFakeRean2002;

TRFakeRean2002.md5 = "1C2E807A38F30573358C5389113BAF95";
TRFakeRean2002.name = "TR/Fake.Rean.2002";

if (filehash == TRFakeRean2002.md5)
{

return TRFakeRean2002.name;

}

Database::Virus TRFakeRean2001;

TRFakeRean2001.md5 = "8F394FBAAA9D38CF40A9154D9F0CD807";
TRFakeRean2001.name = "TR/Fake.Rean.2001";

if (filehash == TRFakeRean2001.md5)
{

return TRFakeRean2001.name;

}

Database::Virus TRFakeRean2000;

TRFakeRean2000.md5 = "CA18B9A0A795F34DDECFF047F63FF188";
TRFakeRean2000.name = "TR/Fake.Rean.2000";

if (filehash == TRFakeRean2000.md5)
{

return TRFakeRean2000.name;

}

Database::Virus TRFakeRean1999;

TRFakeRean1999.md5 = "9F54DCD72E7D4957906E9DE9E1A0B296";
TRFakeRean1999.name = "TR/Fake.Rean.1999";

if (filehash == TRFakeRean1999.md5)
{

return TRFakeRean1999.name;

}

Database::Virus TRFakeRean1998;

TRFakeRean1998.md5 = "104BA1D02328B862E8C68BC8C632563F";
TRFakeRean1998.name = "TR/Fake.Rean.1998";

if (filehash == TRFakeRean1998.md5)
{

return TRFakeRean1998.name;

}

Database::Virus TRFakeRean1997;

TRFakeRean1997.md5 = "697E28E1C92A35F220905F116EDF5D44";
TRFakeRean1997.name = "TR/Fake.Rean.1997";

if (filehash == TRFakeRean1997.md5)
{

return TRFakeRean1997.name;

}

Database::Virus TRFakeRean1996;

TRFakeRean1996.md5 = "3C085FEAA9A7A576D75AFD7F18F394CA";
TRFakeRean1996.name = "TR/Fake.Rean.1996";

if (filehash == TRFakeRean1996.md5)
{

return TRFakeRean1996.name;

}

Database::Virus TRFakeRean1995;

TRFakeRean1995.md5 = "8B5F328F48C8567829F65FACA7D2B06C";
TRFakeRean1995.name = "TR/Fake.Rean.1995";

if (filehash == TRFakeRean1995.md5)
{

return TRFakeRean1995.name;

}

Database::Virus TRFakeRean1994;

TRFakeRean1994.md5 = "C992F2D02FE40EB88E2DF711FBA855A4";
TRFakeRean1994.name = "TR/Fake.Rean.1994";

if (filehash == TRFakeRean1994.md5)
{

return TRFakeRean1994.name;

}

Database::Virus TRFakeRean1993;

TRFakeRean1993.md5 = "A9AA3BBAA007D40037518D01B8C368EF";
TRFakeRean1993.name = "TR/Fake.Rean.1993";

if (filehash == TRFakeRean1993.md5)
{

return TRFakeRean1993.name;

}

Database::Virus TRFakeRean1992;

TRFakeRean1992.md5 = "448937624A77D0E58C51D74F06D04D64";
TRFakeRean1992.name = "TR/Fake.Rean.1992";

if (filehash == TRFakeRean1992.md5)
{

return TRFakeRean1992.name;

}

Database::Virus TRFakeRean1990;

TRFakeRean1990.md5 = "43B180A31F429FEF227317D8ACDD764B";
TRFakeRean1990.name = "TR/Fake.Rean.1990";

if (filehash == TRFakeRean1990.md5)
{

return TRFakeRean1990.name;

}

Database::Virus TRAgentogtv;

TRAgentogtv.md5 = "60272b6e5ae790cbdf271856389d79ee";
TRAgentogtv.name = "TR/Agent.ogtv";

if (filehash == TRAgentogtv.md5)
{

return TRAgentogtv.name;

}

Database::Virus TRLebagcyl1;

TRLebagcyl1.md5 = "9E9ED169D0B7FD75FAA9844E2B5E194B";
TRLebagcyl1.name = "TR/Lebag.cyl.1";

if (filehash == TRLebagcyl1.md5)
{

return TRLebagcyl1.name;

}

Database::Virus TRFakeRean1989;

TRFakeRean1989.md5 = "E5D8173E8EC3A7A94B271C8A238D422A";
TRFakeRean1989.name = "TR/Fake.Rean.1989";

if (filehash == TRFakeRean1989.md5)
{

return TRFakeRean1989.name;

}

Database::Virus TRDropAgentsaf2;

TRDropAgentsaf2.md5 = "427C740704D7C196D1E65E15298437CB";
TRDropAgentsaf2.name = "TR/Drop.Agent.saf.2";

if (filehash == TRDropAgentsaf2.md5)
{

return TRDropAgentsaf2.name;

}

Database::Virus TRDldrScarD;

TRDldrScarD.md5 = "1BF5CFFD41DEE4386A82D4A98DBDDE56";
TRDldrScarD.name = "TR/Dldr.Scar.D";

if (filehash == TRDldrScarD.md5)
{

return TRDldrScarD.name;

}

Database::Virus TRBuzushsfd;

TRBuzushsfd.md5 = "15C93A7FFACA48AE781E9ED2B99408DB";
TRBuzushsfd.name = "TR/Buzus.hsfd";

if (filehash == TRBuzushsfd.md5)
{

return TRBuzushsfd.name;

}

Database::Virus TRJorikSkorB2;

TRJorikSkorB2.md5 = "d486ea2b9454644f9c8cf4350D6a4c01";
TRJorikSkorB2.name = "TR/Jorik.Skor.B.2";

if (filehash == TRJorikSkorB2.md5)
{

return TRJorikSkorB2.name;

}

Database::Virus TRKazy2500072;

TRKazy2500072.md5 = "0759BDA0AE51BED8F7BC1088C9B53AA7";
TRKazy2500072.name = "TR/Kazy.25000.72";

if (filehash == TRKazy2500072.md5)
{

return TRKazy2500072.name;

}

Database::Virus TRYakesli;

TRYakesli.md5 = "A5423C14D3E1BD10791A7B1DA79AE8F5";
TRYakesli.name = "TR/Yakes.li";

if (filehash == TRYakesli.md5)
{

return TRYakesli.name;

}

Database::Virus TRDropTDssakfb;

TRDropTDssakfb.md5 = "60184EE7316CFC9F734CF9713FD76361";
TRDropTDssakfb.name = "TR/Drop.TDss.akfb";

if (filehash == TRDropTDssakfb.md5)
{

return TRDropTDssakfb.name;

}

Database::Virus TRVBKryptdevc1;

TRVBKryptdevc1.md5 = "CF2445B2C06AF8757BB5C598F85BB22E";
TRVBKryptdevc1.name = "TR/VBKrypt.devc.1";

if (filehash == TRVBKryptdevc1.md5)
{

return TRVBKryptdevc1.name;

}

Database::Virus TRVBInjectPX;

TRVBInjectPX.md5 = "9268ADEBF4F49D16DA0838145E8BA4D5";
TRVBInjectPX.name = "TR/VB.Inject.PX";

if (filehash == TRVBInjectPX.md5)
{

return TRVBInjectPX.name;

}

Database::Virus TRVBKryptdhzd;

TRVBKryptdhzd.md5 = "737C8ADD80E92CA17FEEDB27E205189D";
TRVBKryptdhzd.name = "TR/VBKrypt.dhzd";

if (filehash == TRVBKryptdhzd.md5)
{

return TRVBKryptdhzd.name;

}

Database::Virus TRLethicC4;

TRLethicC4.md5 = "56F36F9BE6534237C9A2138B4CD7C2C5";
TRLethicC4.name = "TR/Lethic.C.4";

if (filehash == TRLethicC4.md5)
{

return TRLethicC4.name;

}

Database::Virus TRSpy50227217;

TRSpy50227217.md5 = "5975ab57a890d8a50B42acb0bd0Bc495";
TRSpy50227217.name = "TR/Spy.502272.17";

if (filehash == TRSpy50227217.md5)
{

return TRSpy50227217.name;

}

Database::Virus TRDeedonA;

TRDeedonA.md5 = "5E510AA7FB77DA2C6EA7230D38FC524B";
TRDeedonA.name = "TR/Deedon.A";

if (filehash == TRDeedonA.md5)
{

return TRDeedonA.name;

}

Database::Virus TRBuzusEC95;

TRBuzusEC95.md5 = "ECDBBDEAEB6F7754F1D512B2654CA91C";
TRBuzusEC95.name = "TR/Buzus.EC.95";

if (filehash == TRBuzusEC95.md5)
{

return TRBuzusEC95.name;

}

Database::Virus TRKazy253352;

TRKazy253352.md5 = "81F9A6F10C5D1805221E21F3F6C94A00";
TRKazy253352.name = "TR/Kazy.25335.2";

if (filehash == TRKazy253352.md5)
{

return TRKazy253352.name;

}

Database::Virus TRJorikShakbladesuw1;

TRJorikShakbladesuw1.md5 = "681DBDCCF7F49114A41E84E0DF9B6E0A";
TRJorikShakbladesuw1.name = "TR/Jorik.Shakblades.uw.1";

if (filehash == TRJorikShakbladesuw1.md5)
{

return TRJorikShakbladesuw1.name;

}

Database::Virus TRDldrNirava12741;

TRDldrNirava12741.md5 = "dd300cd046dbb642dd00c4a802769fb9";
TRDldrNirava12741.name = "TR/Dldr.Nirava.127.41";

if (filehash == TRDldrNirava12741.md5)
{

return TRDldrNirava12741.name;

}

Database::Virus TRDldrOpenConnectionAB2;

TRDldrOpenConnectionAB2.md5 = "1175dbef87a27fcf2a5d10e3e2090866";
TRDldrOpenConnectionAB2.name = "TR/Dldr.OpenConnection.AB.2";

if (filehash == TRDldrOpenConnectionAB2.md5)
{

return TRDldrOpenConnectionAB2.name;

}

Database::Virus TRInjector92808;

TRInjector92808.md5 = "70ed6ed4230ab3dd6b6d7d89ee03e64b";
TRInjector92808.name = "TR/Injector.92808";

if (filehash == TRInjector92808.md5)
{

return TRInjector92808.name;

}

Database::Virus TRRimecudA149;

TRRimecudA149.md5 = "01b9d00f1acd2c1e28ce9e63ff67f9e4";
TRRimecudA149.name = "TR/Rimecud.A.149";

if (filehash == TRRimecudA149.md5)
{

return TRRimecudA149.name;

}

Database::Virus TRKazy702710;

TRKazy702710.md5 = "f6f1decae5710e7788ed999bf6e3574b";
TRKazy702710.name = "TR/Kazy.7027.10";

if (filehash == TRKazy702710.md5)
{

return TRKazy702710.name;

}

Database::Virus TRRimecudA804;

TRRimecudA804.md5 = "938173a42b035084340ee6bc5a5ee184";
TRRimecudA804.name = "TR/Rimecud.A.804";

if (filehash == TRRimecudA804.md5)
{

return TRRimecudA804.name;

}

Database::Virus TRDldrOpenConnectionG2;

TRDldrOpenConnectionG2.md5 = "fdad3a9ff9284e8d073b50e1e8636b16";
TRDldrOpenConnectionG2.name = "TR/Dldr.OpenConnection.G.2";

if (filehash == TRDldrOpenConnectionG2.md5)
{

return TRDldrOpenConnectionG2.name;

}

Database::Virus TRRimecudA152;

TRRimecudA152.md5 = "10d34efc9ae4969396d0d109310e9f4a";
TRRimecudA152.name = "TR/Rimecud.A.152";

if (filehash == TRRimecudA152.md5)
{

return TRRimecudA152.name;

}

Database::Virus TRRimecudA151;

TRRimecudA151.md5 = "09b3959c7df29e61fe820d7882d581f7";
TRRimecudA151.name = "TR/Rimecud.A.151";

if (filehash == TRRimecudA151.md5)
{

return TRRimecudA151.name;

}

Database::Virus TRSisronA664;

TRSisronA664.md5 = "08a607c85c5b110240ba3e8b4602a78e";
TRSisronA664.name = "TR/Sisron.A.664";

if (filehash == TRSisronA664.md5)
{

return TRSisronA664.name;

}

Database::Virus TRVbotF6;

TRVbotF6.md5 = "bb6068b96602fa34ac89a3fd1257871e";
TRVbotF6.name = "TR/Vbot.F.6";

if (filehash == TRVbotF6.md5)
{

return TRVbotF6.name;

}

Database::Virus TRVBCryptCP11;

TRVBCryptCP11.md5 = "ec90f9b04ab2b374161ce51ce8994b69";
TRVBCryptCP11.name = "TR/VBCrypt.CP.11";

if (filehash == TRVBCryptCP11.md5)
{

return TRVBCryptCP11.name;

}

Database::Virus TRAgentzql1;

TRAgentzql1.md5 = "496403ddd7cb31d73805f32f749ce59b";
TRAgentzql1.name = "TR/Agent.zql.1";

if (filehash == TRAgentzql1.md5)
{

return TRAgentzql1.name;

}

Database::Virus TRVBKryptctyp;

TRVBKryptctyp.md5 = "b17691741cbc89df1cab72437372471e";
TRVBKryptctyp.name = "TR/VBKrypt.ctyp";

if (filehash == TRVBKryptctyp.md5)
{

return TRVBKryptctyp.name;

}

Database::Virus TRAgent77824;

TRAgent77824.md5 = "3e6dc704fc07eecd9628c1bb3969ac56";
TRAgent77824.name = "TR/Agent.77824";

if (filehash == TRAgent77824.md5)
{

return TRAgent77824.name;

}

Database::Virus TRRimecud95374;

TRRimecud95374.md5 = "61b582ec6a027b4a69a2d4da36a934ff";
TRRimecud95374.name = "TR/Rimecud.95374";

if (filehash == TRRimecud95374.md5)
{

return TRRimecud95374.name;

}

Database::Virus TRGendal59867881;

TRGendal59867881.md5 = "ce98687b497c34fd9857e0ff8d568f5a";
TRGendal59867881.name = "TR/Gendal.5986788.1";

if (filehash == TRGendal59867881.md5)
{

return TRGendal59867881.name;

}

Database::Virus TRBuzusgzap;

TRBuzusgzap.md5 = "2B64C4E3C66C1D852CC1A5893F18E0B3";
TRBuzusgzap.name = "TR/Buzus.gzap";

if (filehash == TRBuzusgzap.md5)
{

return TRBuzusgzap.name;

}

Database::Virus TRAgentCO3;

TRAgentCO3.md5 = "1621aa2ba27ebc2c3823f3113ff3a836";
TRAgentCO3.name = "TR/Agent.CO.3";

if (filehash == TRAgentCO3.md5)
{

return TRAgentCO3.name;

}

Database::Virus TRVBaga166;

TRVBaga166.md5 = "d54cbd070378e655f398979ac7caca5c";
TRVBaga166.name = "TR/VB.aga.166";

if (filehash == TRVBaga166.md5)
{

return TRVBaga166.name;

}

Database::Virus TRVBaga168;

TRVBaga168.md5 = "79d5ea6fa8208fd76edfc9b99df1c280";
TRVBaga168.name = "TR/VB.aga.168";

if (filehash == TRVBaga168.md5)
{

return TRVBaga168.name;

}

Database::Virus TREyeStyeN107;

TREyeStyeN107.md5 = "9D2FC019B4B7582C7AFD0D5D55E23449";
TREyeStyeN107.name = "TR/EyeStye.N.107";

if (filehash == TREyeStyeN107.md5)
{

return TREyeStyeN107.name;

}

Database::Virus TRVBaga167;

TRVBaga167.md5 = "45bcbb56dcfb68200719163a933c4f6c";
TRVBaga167.name = "TR/VB.aga.167";

if (filehash == TRVBaga167.md5)
{

return TRVBaga167.name;

}

Database::Virus TRVaklikkrs;

TRVaklikkrs.md5 = "6651b1bda6a059855512989a360df4db";
TRVaklikkrs.name = "TR/Vaklik.krs";

if (filehash == TRVaklikkrs.md5)
{

return TRVaklikkrs.name;

}

Database::Virus TRSpyeyeAK;

TRSpyeyeAK.md5 = "d86475833d1edf6838acade9827f42f2";
TRSpyeyeAK.name = "TR/Spyeye.AK";

if (filehash == TRSpyeyeAK.md5)
{

return TRSpyeyeAK.name;

}

Database::Virus TRSpyEyesK;

TRSpyEyesK.md5 = "d70e0a9bde5e93da1f3861263c0f0deb";
TRSpyEyesK.name = "TR/SpyEyes.K";

if (filehash == TRSpyEyesK.md5)
{

return TRSpyEyesK.name;

}

Database::Virus TRSpyZBotRS1;

TRSpyZBotRS1.md5 = "948ba9e36338cfd2a789b8a49094fefb";
TRSpyZBotRS1.name = "TR/Spy.ZBot.RS.1";

if (filehash == TRSpyZBotRS1.md5)
{

return TRSpyZBotRS1.name;

}

Database::Virus TREyeStyeN208;

TREyeStyeN208.md5 = "2ff71e989e3154357a2acf20e73785ae";
TREyeStyeN208.name = "TR/EyeStye.N.208";

if (filehash == TREyeStyeN208.md5)
{

return TREyeStyeN208.name;

}

Database::Virus TRRimecudA146;

TRRimecudA146.md5 = "64E827D7D3136FF93985AAA4158A51EB";
TRRimecudA146.name = "TR/Rimecud.A.146";

if (filehash == TRRimecudA146.md5)
{

return TRRimecudA146.name;

}

Database::Malware TRKazy2938728;

TRKazy2938728.md5 = "052ff334a9fb0eda83eaa514e304d01d";
TRKazy2938728.name = "TR/Kazy.29387.28";

if (filehash == TRKazy2938728.md5)
{

return TRKazy2938728.name;

}

Database::Virus TRArchSMSrdz482;

TRArchSMSrdz482.md5 = "03f671ff0aaeea463157d37e4dbeac9f";
TRArchSMSrdz482.name = "TR/ArchSMS.rdz.482";

if (filehash == TRArchSMSrdz482.md5)
{

return TRArchSMSrdz482.name;

}

Database::Virus TRScardhcr;

TRScardhcr.md5 = "a111960c03d8e33339a13be23ff07d9d";
TRScardhcr.name = "TR/Scar.dhcr";

if (filehash == TRScardhcr.md5)
{

return TRScardhcr.name;

}

Database::Virus TRSpySpyeyeQ;

TRSpySpyeyeQ.md5 = "50f8359a41e5eaa938b0b1c4b564bdf3";
TRSpySpyeyeQ.name = "TR/Spy.Spyeye.Q";

if (filehash == TRSpySpyeyeQ.md5)
{

return TRSpySpyeyeQ.name;

}

Database::Virus TRPincavanth;

TRPincavanth.md5 = "19797e5f4274bea0f287178b7c32fc5a";
TRPincavanth.name = "TR/Pincav.anth";

if (filehash == TRPincavanth.md5)
{

return TRPincavanth.name;

}

Database::Virus TRDldrGenomeaknh;

TRDldrGenomeaknh.md5 = "CAF89E14A9AC994907E779F1720C1320";
TRDldrGenomeaknh.name = "TR/Dldr.Genome.aknh";

if (filehash == TRDldrGenomeaknh.md5)
{

return TRDldrGenomeaknh.name;

}

Database::Virus TRDldrVBacyt;

TRDldrVBacyt.md5 = "e236663e37905f7cdbb3b7c1b3535c2b";
TRDldrVBacyt.name = "TR/Dldr.VB.acyt";

if (filehash == TRDldrVBacyt.md5)
{

return TRDldrVBacyt.name;

}

Database::Virus TRJorikIRCbotzs;

TRJorikIRCbotzs.md5 = "ef171f2bf7bfbe57727a30bcdb3f7442";
TRJorikIRCbotzs.name = "TR/Jorik.IRCbot.zs";

if (filehash == TRJorikIRCbotzs.md5)
{

return TRJorikIRCbotzs.name;

}

Database::Virus TRInjectorQ16;

TRInjectorQ16.md5 = "bd3d6f870dd82bd04d59da8baf2211be";
TRInjectorQ16.name = "TR/Injector.Q.16";

if (filehash == TRInjectorQ16.md5)
{

return TRInjectorQ16.name;

}

Database::Virus TRDldrAgentACF2;

TRDldrAgentACF2.md5 = "b833592a74de77b652e21cf9a6d0a9de";
TRDldrAgentACF2.name = "TR/Dldr.Agent.ACF.2";

if (filehash == TRDldrAgentACF2.md5)
{

return TRDldrAgentACF2.name;

}

Database::Virus TRVBInjectGJ1;

TRVBInjectGJ1.md5 = "e886a4d9b9909639f95a48872c5dbc07";
TRVBInjectGJ1.name = "TR/VB.Inject.GJ.1";

if (filehash == TRVBInjectGJ1.md5)
{

return TRVBInjectGJ1.name;

}

Database::Virus TRAgent86016;

TRAgent86016.md5 = "b33fd2986984b06065b21712d6385b9a";
TRAgent86016.name = "TR/Agent.86016";

if (filehash == TRAgent86016.md5)
{

return TRAgent86016.name;

}

Database::Virus TRAgent270336;

TRAgent270336.md5 = "3cd19c2520fa9a8682b81a13a04eba86";
TRAgent270336.name = "TR/Agent.270336";

if (filehash == TRAgent270336.md5)
{

return TRAgent270336.name;

}

Database::Virus TRKazy2515910;

TRKazy2515910.md5 = "7961119d5e4b518ab81f99f67b90ed00";
TRKazy2515910.name = "TR/Kazy.25159.10";

if (filehash == TRKazy2515910.md5)
{

return TRKazy2515910.name;

}

Database::Virus TRKazy2033298;

TRKazy2033298.md5 = "41e44019e81682c991ccc9fdd62f99dd";
TRKazy2033298.name = "TR/Kazy.20332.98";

if (filehash == TRKazy2033298.md5)
{

return TRKazy2033298.name;

}

Database::Virus TRKazy2473212;

TRKazy2473212.md5 = "137d614bcab51797b4be6b6cac0016b6";
TRKazy2473212.name = "TR/Kazy.24732.12";

if (filehash == TRKazy2473212.md5)
{

return TRKazy2473212.name;

}

Database::Virus TRKazy1996793;

TRKazy1996793.md5 = "08120d644f58ca9c67f915479cc28209";
TRKazy1996793.name = "TR/Kazy.19967.93";

if (filehash == TRKazy1996793.md5)
{

return TRKazy1996793.name;

}

Database::Virus TRSpyUrsnif680;

TRSpyUrsnif680.md5 = "4f0a52dd9688c344de62a16e77759460";
TRSpyUrsnif680.name = "TR/Spy.Ursnif.680";

if (filehash == TRSpyUrsnif680.md5)
{

return TRSpyUrsnif680.name;

}

Database::Virus TRDropDapatodrl;

TRDropDapatodrl.md5 = "08f89856fb2a72f2d45b09c401aa8915";
TRDropDapatodrl.name = "TR/Drop.Dapato.drl";

if (filehash == TRDropDapatodrl.md5)
{

return TRDropDapatodrl.name;

}

Database::Virus TRFakeRean3549;

TRFakeRean3549.md5 = "0e03af7aff665b8ae64a523854fd61ea";
TRFakeRean3549.name = "TR/Fake.Rean.3549";

if (filehash == TRFakeRean3549.md5)
{

return TRFakeRean3549.name;

}

Database::Virus TRFakeRean3548;

TRFakeRean3548.md5 = "2b43e78be6c9183c875b24ac3f84d1fe";
TRFakeRean3548.name = "TR/Fake.Rean.3548";

if (filehash == TRFakeRean3548.md5)
{

return TRFakeRean3548.name;

}

Database::Virus TRKazy284702;

TRKazy284702.md5 = "356CE23D537D7533720DDA818D95EFC5";
TRKazy284702.name = "TR/Kazy.28470.2";

if (filehash == TRKazy284702.md5)
{

return TRKazy284702.name;

}

Database::Virus TRBuzushmxh;

TRBuzushmxh.md5 = "21a5776cac8cea4aae3785b9cef66cf2";
TRBuzushmxh.name = "TR/Buzus.hmxh";

if (filehash == TRBuzushmxh.md5)
{

return TRBuzushmxh.name;

}

Database::Virus TRDldrCutwailBA28;

TRDldrCutwailBA28.md5 = "97af57ce4937a43fd93fe0ae13544dc8";
TRDldrCutwailBA28.name = "TR/Dldr.Cutwail.BA.28";

if (filehash == TRDldrCutwailBA28.md5)
{

return TRDldrCutwailBA28.name;

}

Database::Virus TRMalexF29;

TRMalexF29.md5 = "928f136bd81da0c8f6218ef89fcec7bd";
TRMalexF29.name = "TR/Malex.F.29";

if (filehash == TRMalexF29.md5)
{

return TRMalexF29.name;

}

Database::Virus TRDropInjectora1;

TRDropInjectora1.md5 = "116049c233e5e04eb26c67b54c8f3177";
TRDropInjectora1.name = "TR/Drop.Injector.a.1";

if (filehash == TRDropInjectora1.md5)
{

return TRDropInjectora1.name;

}

Database::Virus TRDldrCutwailBF2;

TRDldrCutwailBF2.md5 = "7ac1f56ae2c71a4ee4257e4590871451";
TRDldrCutwailBF2.name = "TR/Dldr.Cutwail.BF.2";

if (filehash == TRDldrCutwailBF2.md5)
{

return TRDldrCutwailBF2.name;

}

Database::Virus TRSpyZBottac;

TRSpyZBottac.md5 = "53833a7ef5798bb910640f92c6b0cf3e";
TRSpyZBottac.name = "TR/Spy.ZBot.tac";

if (filehash == TRSpyZBottac.md5)
{

return TRSpyZBottac.name;

}

Database::Virus TRDldrPeltpoxA;

TRDldrPeltpoxA.md5 = "184787a974f78f3846081cfabc5234bd";
TRDldrPeltpoxA.name = "TR/Dldr.Peltpox.A";

if (filehash == TRDldrPeltpoxA.md5)
{

return TRDldrPeltpoxA.name;

}

Database::Virus TRDropKipA;

TRDropKipA.md5 = "d6c5d0e7a74595ffe2f4482a50ad654e";
TRDropKipA.name = "TR/Drop.Kip.A";

if (filehash == TRDropKipA.md5)
{

return TRDropKipA.name;

}

Database::Virus TRVBKrypt419;

TRVBKrypt419.md5 = "159fd90abcbeb6039ff56d071d668ced";
TRVBKrypt419.name = "TR/VBKrypt.41.9";

if (filehash == TRVBKrypt419.md5)
{

return TRVBKrypt419.name;

}

Database::Virus TRDldrKaraganyB;

TRDldrKaraganyB.md5 = "8ce8994f757b3d78575db434da0c1155";
TRDldrKaraganyB.name = "TR/Dldr.Karagany.B";

if (filehash == TRDldrKaraganyB.md5)
{

return TRDldrKaraganyB.name;

}

Database::Virus TRFakeAVahx1;

TRFakeAVahx1.md5 = "638f60ed1fd4531ca50d6b4cd29bd0dd";
TRFakeAVahx1.name = "TR/FakeAV.ahx.1";

if (filehash == TRFakeAVahx1.md5)
{

return TRFakeAVahx1.name;

}

Database::Virus TRIrcbruteA592;

TRIrcbruteA592.md5 = "aafbb1f62b54fdf603bdbf81345e11f1";
TRIrcbruteA592.name = "TR/Ircbrute.A.592";

if (filehash == TRIrcbruteA592.md5)
{

return TRIrcbruteA592.name;

}

Database::Virus TRAgent90112BD;

TRAgent90112BD.md5 = "7b939100f7585fd7e08be6236b03de24";
TRAgent90112BD.name = "TR/Agent.90112.BD";

if (filehash == TRAgent90112BD.md5)
{

return TRAgent90112BD.name;

}

Database::Virus TRFakeAVahw1;

TRFakeAVahw1.md5 = "27A040A6DF0453F2B13FCCC082866CE7";
TRFakeAVahw1.name = "TR/FakeAV.ahw.1";

if (filehash == TRFakeAVahw1.md5)
{

return TRFakeAVahw1.name;

}

Database::Virus TRSpyZBotPU;

TRSpyZBotPU.md5 = "5f720c94795483a61e92acd4ccf74b44";
TRSpyZBotPU.name = "TR/Spy.ZBot.PU";

if (filehash == TRSpyZBotPU.md5)
{

return TRSpyZBotPU.name;

}

Database::Virus TRRefroso4295685;

TRRefroso4295685.md5 = "45bf31069aa64c6054052e39bdf983fa";
TRRefroso4295685.name = "TR/Refroso.4295685";

if (filehash == TRRefroso4295685.md5)
{

return TRRefroso4295685.name;

}

Database::Virus TRSpyFarkoh;

TRSpyFarkoh.md5 = "7AC5C984931B7BFF932EDE9E7C20EFE8";
TRSpyFarkoh.name = "TR/Spy.Farko.h";

if (filehash == TRSpyFarkoh.md5)
{

return TRSpyFarkoh.name;

}

Database::Virus TRSpyAgentbrbq;

TRSpyAgentbrbq.md5 = "CEDA074F9C459EAC39587FC4CDFF9405";
TRSpyAgentbrbq.name = "TR/Spy.Agent.brbq";

if (filehash == TRSpyAgentbrbq.md5)
{

return TRSpyAgentbrbq.name;

}

Database::Virus TRJavaClassLoaderAP;

TRJavaClassLoaderAP.md5 = "b9b70b794049b2a5a161cf1d23087d76";
TRJavaClassLoaderAP.name = "TR/Java.ClassLoader.AP";

if (filehash == TRJavaClassLoaderAP.md5)
{

return TRJavaClassLoaderAP.name;

}

Database::Virus TRRansomPornoAssetfs;

TRRansomPornoAssetfs.md5 = "5ebac09dc2625880b8cf0f7cc5f6fbfb";
TRRansomPornoAssetfs.name = "TR/Ransom.PornoAsset.fs";

if (filehash == TRRansomPornoAssetfs.md5)
{

return TRRansomPornoAssetfs.name;

}

Database::Virus TRCoremheadA61;

TRCoremheadA61.md5 = "D09E0D0FBAAC7DE4E4EF6E68EBC91AC8";
TRCoremheadA61.name = "TR/Coremhead.A.61";

if (filehash == TRCoremheadA61.md5)
{

return TRCoremheadA61.name;

}

Database::Virus TRMentijel;

TRMentijel.md5 = "dd2bb85d319ba84557188205855def4b";
TRMentijel.name = "TR/Menti.jel";

if (filehash == TRMentijel.md5)
{

return TRMentijel.name;

}

Database::Virus TRJavaClassLoaderAP1;

TRJavaClassLoaderAP1.md5 = "03191890da4a00e352fee4235478a9d0";
TRJavaClassLoaderAP1.name = "TR/Java.ClassLoader.AP.1";

if (filehash == TRJavaClassLoaderAP1.md5)
{

return TRJavaClassLoaderAP1.name;

}

Database::Virus TRDropAgentare1;

TRDropAgentare1.md5 = "36922b88924674323f73812513718e74";
TRDropAgentare1.name = "TR/Drop.Agent.are.1";

if (filehash == TRDropAgentare1.md5)
{

return TRDropAgentare1.name;

}

Database::Virus TRDldrAgentserv;

TRDldrAgentserv.md5 = "F37A9A04EBC9BC6311A28B75215F1B66";
TRDldrAgentserv.name = "TR/Dldr.Agent.serv";

if (filehash == TRDldrAgentserv.md5)
{

return TRDldrAgentserv.name;

}

Database::Virus TRDldrHarnigS241;

TRDldrHarnigS241.md5 = "9003ddfd1b2bed163d70b64700bc8e9f";
TRDldrHarnigS241.name = "TR/Dldr.Harnig.S.241";

if (filehash == TRDldrHarnigS241.md5)
{

return TRDldrHarnigS241.name;

}

Database::Virus TRFakeRean1608;

TRFakeRean1608.md5 = "646c72d0102e85458cd6f6be818ced07";
TRFakeRean1608.name = "TR/Fake.Rean.1608";

if (filehash == TRFakeRean1608.md5)
{

return TRFakeRean1608.name;

}

Database::Virus TRObfuscatorpsb;

TRObfuscatorpsb.md5 = "57e5fd58bebc524c6dd7c59d222d92f3";
TRObfuscatorpsb.name = "TR/Obfuscator.psb";

if (filehash == TRObfuscatorpsb.md5)
{

return TRObfuscatorpsb.name;

}

Database::Virus TRSpyZBotbkaa;

TRSpyZBotbkaa.md5 = "cbb8611337f0435726d4d504d1c9e3c3";
TRSpyZBotbkaa.name = "TR/Spy.ZBot.bkaa";

if (filehash == TRSpyZBotbkaa.md5)
{

return TRSpyZBotbkaa.name;

}

Database::Virus TRSpyeyeH17;

TRSpyeyeH17.md5 = "05a2d7b4d816c392632e40ac34a9d886";
TRSpyeyeH17.name = "TR/Spyeye.H.17";

if (filehash == TRSpyeyeH17.md5)
{

return TRSpyeyeH17.name;

}

Database::Virus TRJorikSdBotne;

TRJorikSdBotne.md5 = "288d9855e9de0cfcee73d02fef6668af";
TRJorikSdBotne.name = "TR/Jorik.SdBot.ne";

if (filehash == TRJorikSdBotne.md5)
{

return TRJorikSdBotne.name;

}

Database::Virus TRInjector68612;

TRInjector68612.md5 = "92ef611bc1f15a9eec5648b33d325cbf";
TRInjector68612.name = "TR/Injector.68612";

if (filehash == TRInjector68612.md5)
{

return TRInjector68612.name;

}

Database::Virus TRSpy24934420;

TRSpy24934420.md5 = "78415f430f79382ac9dd377b806c52be";
TRSpy24934420.name = "TR/Spy.249344.20";

if (filehash == TRSpy24934420.md5)
{

return TRSpy24934420.name;

}

Database::Virus TRSpy32422;

TRSpy32422.md5 = "2dc74c3c32be232df6e50dd3e0247d4c";
TRSpy32422.name = "TR/Spy.32422";

if (filehash == TRSpy32422.md5)
{

return TRSpy32422.name;

}

Database::Virus TRWebprefixB11;

TRWebprefixB11.md5 = "5521CF04D36588089A2263DB35CE7579";
TRWebprefixB11.name = "TR/Webprefix.B.11";

if (filehash == TRWebprefixB11.md5)
{

return TRWebprefixB11.name;

}

Database::Virus TRDldrSmallCD;

TRDldrSmallCD.md5 = "63c25b44951de483ad5b566c8c89be2c";
TRDldrSmallCD.name = "TR/Dldr.Small.CD";

if (filehash == TRDldrSmallCD.md5)
{

return TRDldrSmallCD.name;

}

Database::Virus TRAgent184320;

TRAgent184320.md5 = "49537c2c00a30d749fc39e4dd141f04a";
TRAgent184320.name = "TR/Agent.184320";

if (filehash == TRAgent184320.md5)
{

return TRAgent184320.name;

}

Database::Virus TRPSWMaganiaerbp6;

TRPSWMaganiaerbp6.md5 = "76ED8C04864C7A6A944ECDD0C9E93951";
TRPSWMaganiaerbp6.name = "TR/PSW.Magania.erbp.6";

if (filehash == TRPSWMaganiaerbp6.md5)
{

return TRPSWMaganiaerbp6.name;

}

Database::Virus TRAgent151552;

TRAgent151552.md5 = "fe61987d2bd3dc09abeae4b75839098f";
TRAgent151552.name = "TR/Agent.151552";

if (filehash == TRAgent151552.md5)
{

return TRAgent151552.name;

}

Database::Virus TRKillsys143870;

TRKillsys143870.md5 = "fc0acbeb586c307e99e5d758448f8eaf";
TRKillsys143870.name = "TR/Killsys.143870";

if (filehash == TRKillsys143870.md5)
{

return TRKillsys143870.name;

}

Database::Virus TRKazy22993;

TRKazy22993.md5 = "097B909BDBAB380F295C1F1AD216594E";
TRKazy22993.name = "TR/Kazy.22993";

if (filehash == TRKazy22993.md5)
{

return TRKazy22993.name;

}

Database::Virus TRDldrKingaA;

TRDldrKingaA.md5 = "2fa087bce41a46ca2ce19af7902a4997";
TRDldrKingaA.name = "TR/Dldr.Kinga.A";

if (filehash == TRDldrKingaA.md5)
{

return TRDldrKingaA.name;

}

Database::Virus TRDropfakA;

TRDropfakA.md5 = "3884c9021f21134089277eb5212f7e29";
TRDropfakA.name = "TR/Drop.fak.A";

if (filehash == TRDropfakA.md5)
{

return TRDropfakA.name;

}

Database::Virus TRDldrFakeDwmE;

TRDldrFakeDwmE.md5 = "f2e0fb3da79befe5ad4b4757a35a080d";
TRDldrFakeDwmE.name = "TR/Dldr.FakeDwm.E";

if (filehash == TRDldrFakeDwmE.md5)
{

return TRDldrFakeDwmE.name;

}

Database::Virus TRKazy14157psa;

TRKazy14157psa.md5 = "f8a04bdc899dce32d22ef592f1f1d2e6";
TRKazy14157psa.name = "TR/Kazy.14157.psa";

if (filehash == TRKazy14157psa.md5)
{

return TRKazy14157psa.name;

}

Database::Virus TRAgent2283527;

TRAgent2283527.md5 = "4bb8ea7612c5d990725d95948ecab1d3";
TRAgent2283527.name = "TR/Agent.228352.7";

if (filehash == TRAgent2283527.md5)
{

return TRAgent2283527.name;

}

Database::Virus TRSpySpyEyesffc;

TRSpySpyEyesffc.md5 = "5d9a3550513b1e81967a644701280b81";
TRSpySpyEyesffc.name = "TR/Spy.SpyEyes.ffc";

if (filehash == TRSpySpyEyesffc.md5)
{

return TRSpySpyEyesffc.name;

}

Database::Virus TRQhostvqe;

TRQhostvqe.md5 = "9b861ef3a588a413a8fa82e6c2497989";
TRQhostvqe.name = "TR/Qhost.vqe";

if (filehash == TRQhostvqe.md5)
{

return TRQhostvqe.name;

}

Database::Virus TROficlaKC;

TROficlaKC.md5 = "64901cfdfb576d7c7c1d4f1f240315e2";
TROficlaKC.name = "TR/Oficla.KC";

if (filehash == TROficlaKC.md5)
{

return TROficlaKC.name;

}

Database::Virus TRAgentvpet;

TRAgentvpet.md5 = "00b2d12b96e02a23891d1eb4e55edb7e";
TRAgentvpet.name = "TR/Agent.vpet";

if (filehash == TRAgentvpet.md5)
{

return TRAgentvpet.name;

}

Database::Virus TRAgentARHS;

TRAgentARHS.md5 = "e5623a497167d8a6c98e2e6b0293577d";
TRAgentARHS.name = "TR/Agent.ARHS";

if (filehash == TRAgentARHS.md5)
{

return TRAgentARHS.name;

}

Database::Virus TRDropAgentFR;

TRDropAgentFR.md5 = "e7c679d6d83912beb8ccaf6b738fbbec";
TRDropAgentFR.name = "TR/Drop.Agent.FR";

if (filehash == TRDropAgentFR.md5)
{

return TRDropAgentFR.name;

}

Database::Virus TRDropAgentDM;

TRDropAgentDM.md5 = "b19dfbf239ec64aab8e59a87bac69a49";
TRDropAgentDM.name = "TR/Drop.Agent.DM";

if (filehash == TRDropAgentDM.md5)
{

return TRDropAgentDM.name;

}

Database::Virus TRSpy40960018;

TRSpy40960018.md5 = "07beacadb4370c139a18d8ab7e3f5578";
TRSpy40960018.name = "TR/Spy.409600.18";

if (filehash == TRSpy40960018.md5)
{

return TRSpy40960018.name;

}

Database::Virus TRCruxB;

TRCruxB.md5 = "ed69a886cf53f6195f764be61b42876c";
TRCruxB.name = "TR/Crux.B";

if (filehash == TRCruxB.md5)
{

return TRCruxB.name;

}

Database::Virus TRCruxA;

TRCruxA.md5 = "9166ac9fa8e0df448e53d7a6053c74ef";
TRCruxA.name = "TR/Crux.A";

if (filehash == TRCruxA.md5)
{

return TRCruxA.name;

}

Database::Virus TRDldrfakA;

TRDldrfakA.md5 = "d35ebe3d333225a9b5f509ff5daef84c";
TRDldrfakA.name = "TR/Dldr.fak.A";

if (filehash == TRDldrfakA.md5)
{

return TRDldrfakA.name;

}

Database::Virus TRDiplecup44;

TRDiplecup44.md5 = "4272aa436424d1dfdd1674621554a11e";
TRDiplecup44.name = "TR/Diple.cup.44";

if (filehash == TRDiplecup44.md5)
{

return TRDiplecup44.name;

}

Database::Virus TRIrcbruteA219;

TRIrcbruteA219.md5 = "ff90862c768ce5498be6c37aaf1bf703";
TRIrcbruteA219.name = "TR/Ircbrute.A.219";

if (filehash == TRIrcbruteA219.md5)
{

return TRIrcbruteA219.name;

}

Database::Virus TRSpy1858560;

TRSpy1858560.md5 = "ea48d9b70e99f14d296d648cdec59459";
TRSpy1858560.name = "TR/Spy.1858560";

if (filehash == TRSpy1858560.md5)
{

return TRSpy1858560.name;

}

Database::Virus TRDropStartPageDox6;

TRDropStartPageDox6.md5 = "e83192beda892c5539c84e4550dc4756";
TRDropStartPageDox6.name = "TR/Drop.StartPage.Dox.6";

if (filehash == TRDropStartPageDox6.md5)
{

return TRDropStartPageDox6.name;

}

Database::Virus TRFakealertYI;

TRFakealertYI.md5 = "797181dc2d686cf32e53e52f4cf6967c";
TRFakealertYI.name = "TR/Fakealert.YI";

if (filehash == TRFakealertYI.md5)
{

return TRFakealertYI.name;

}

Database::Virus TRAgentig81;

TRAgentig81.md5 = "9c32c5bec9997eb182fd3a416d2c8e7b";
TRAgentig81.name = "TR/Agent.ig.81";

if (filehash == TRAgentig81.md5)
{

return TRAgentig81.name;

}

Database::Virus TRAgentig4;

TRAgentig4.md5 = "56d4bda419e9d8798390dbbda36f12d1";
TRAgentig4.name = "TR/Agent.ig.4";

if (filehash == TRAgentig4.md5)
{

return TRAgentig4.name;

}

Database::Virus TRAgentig2;

TRAgentig2.md5 = "51a8c71bd2ca23c2c55109b1c3d5719b";
TRAgentig2.name = "TR/Agent.ig.2";

if (filehash == TRAgentig2.md5)
{

return TRAgentig2.name;

}

Database::Virus TRJorikSpyEyesmx;

TRJorikSpyEyesmx.md5 = "f686395ca15b7fbc9d5d0a9e33c08cdc";
TRJorikSpyEyesmx.name = "TR/Jorik.SpyEyes.mx";

if (filehash == TRJorikSpyEyesmx.md5)
{

return TRJorikSpyEyesmx.name;

}

Database::Virus TRDldrKazyBC;

TRDldrKazyBC.md5 = "9caf5da08ab00b81b5293f7a320810bc";
TRDldrKazyBC.name = "TR/Dldr.Kazy.BC";

if (filehash == TRDldrKazyBC.md5)
{

return TRDldrKazyBC.name;

}

Database::Virus TRDldrFraudLoE2;

TRDldrFraudLoE2.md5 = "63ba0a6cd28bc150fc8d39a464be0ccc";
TRDldrFraudLoE2.name = "TR/Dldr.FraudLo.E.2";

if (filehash == TRDldrFraudLoE2.md5)
{

return TRDldrFraudLoE2.name;

}

Database::Virus TRDldrFraudLoG3;

TRDldrFraudLoG3.md5 = "723763f39734c6b8a3cb7cdf1b84ffc6";
TRDldrFraudLoG3.name = "TR/Dldr.FraudLo.G.3";

if (filehash == TRDldrFraudLoG3.md5)
{

return TRDldrFraudLoG3.name;

}

Database::Virus TRKazy23438;

TRKazy23438.md5 = "921b879953f34f87a0324c8bbd1e6e17";
TRKazy23438.name = "TR/Kazy.23438";

if (filehash == TRKazy23438.md5)
{

return TRKazy23438.name;

}

Database::Virus TRDldrFraudLoE4;

TRDldrFraudLoE4.md5 = "993233f51cb477bbbc244785608698ef";
TRDldrFraudLoE4.name = "TR/Dldr.FraudLo.E.4";

if (filehash == TRDldrFraudLoE4.md5)
{

return TRDldrFraudLoE4.name;

}

Database::Virus TRDldrFraudLoF4;

TRDldrFraudLoF4.md5 = "360a42d60e886f7eca51c567bb307b67";
TRDldrFraudLoF4.name = "TR/Dldr.FraudLo.F.4";

if (filehash == TRDldrFraudLoF4.md5)
{

return TRDldrFraudLoF4.name;

}

Database::Virus TRDldrKazyC;

TRDldrKazyC.md5 = "9819320fcea7a99d521e000bbbb53ef8";
TRDldrKazyC.name = "TR/Dldr.Kazy.C";

if (filehash == TRDldrKazyC.md5)
{

return TRDldrKazyC.name;

}

Database::Virus TRInjectorDC5;

TRInjectorDC5.md5 = "0acc9eaadd483b8ce9dd2a87aaa0dbe7";
TRInjectorDC5.name = "TR/Injector.DC.5";

if (filehash == TRInjectorDC5.md5)
{

return TRInjectorDC5.name;

}

Database::Virus TRPincavaxub;

TRPincavaxub.md5 = "d229d0af97d7f929107430f8ea2cff5b";
TRPincavaxub.name = "TR/Pincav.axub";

if (filehash == TRPincavaxub.md5)
{

return TRPincavaxub.name;

}

Database::Virus TRPincavaxtv;

TRPincavaxtv.md5 = "ce788987c1f24614c8ac23939c5f7265";
TRPincavaxtv.name = "TR/Pincav.axtv";

if (filehash == TRPincavaxtv.md5)
{

return TRPincavaxtv.name;

}

Database::Virus TRExtatsA39;

TRExtatsA39.md5 = "2eab29682efa6513c87f3a8ae2df7854";
TRExtatsA39.name = "TR/Extats.A.39";

if (filehash == TRExtatsA39.md5)
{

return TRExtatsA39.name;

}

Database::Virus TRDldrKazyBK;

TRDldrKazyBK.md5 = "9e66b749c42cdfc38581d050ad1740de";
TRDldrKazyBK.name = "TR/Dldr.Kazy.BK";

if (filehash == TRDldrKazyBK.md5)
{

return TRDldrKazyBK.name;

}

Database::Virus TRKazyDX;

TRKazyDX.md5 = "96337adca15ac2ad5678b3a5ce6c790b";
TRKazyDX.name = "TR/Kazy.DX";

if (filehash == TRKazyDX.md5)
{

return TRKazyDX.name;

}

Database::Virus TRKazyDW;

TRKazyDW.md5 = "d4d66488a1cadfc9a0cd72bd80b79be8";
TRKazyDW.name = "TR/Kazy.DW";

if (filehash == TRKazyDW.md5)
{

return TRKazyDW.name;

}

Database::Virus TRPSWOnlineGamesxoge;

TRPSWOnlineGamesxoge.md5 = "c171999739068343a1899041303fe7ab";
TRPSWOnlineGamesxoge.name = "TR/PSW.OnlineGames.xoge";

if (filehash == TRPSWOnlineGamesxoge.md5)
{

return TRPSWOnlineGamesxoge.name;

}

Database::Virus TRDldrRenosPG91;

TRDldrRenosPG91.md5 = "019d0480f15b53565559ae265642fc13";
TRDldrRenosPG91.name = "TR/Dldr.Renos.PG.91";

if (filehash == TRDldrRenosPG91.md5)
{

return TRDldrRenosPG91.name;

}

Database::Virus TRDldrRenosPG90;

TRDldrRenosPG90.md5 = "ea2fed38f82fe6f2209d3efe1045a32e";
TRDldrRenosPG90.name = "TR/Dldr.Renos.PG.90";

if (filehash == TRDldrRenosPG90.md5)
{

return TRDldrRenosPG90.name;

}

Database::Virus TRPSWMaganiaR;

TRPSWMaganiaR.md5 = "03b3b534f4964f324d36e7e4f3e6898d";
TRPSWMaganiaR.name = "TR/PSW.Magania.R";

if (filehash == TRPSWMaganiaR.md5)
{

return TRPSWMaganiaR.name;

}

Database::Virus TRDldrAgentpod;

TRDldrAgentpod.md5 = "a62378c4ecfda5fced6c408333d4dfe5";
TRDldrAgentpod.name = "TR/Dldr.Agent.pod";

if (filehash == TRDldrAgentpod.md5)
{

return TRDldrAgentpod.name;

}

Database::Virus TRDldrChepvilI5;

TRDldrChepvilI5.md5 = "08ba3c182674398cd2190cad5dc327ef";
TRDldrChepvilI5.name = "TR/Dldr.Chepvil.I.5";

if (filehash == TRDldrChepvilI5.md5)
{

return TRDldrChepvilI5.name;

}

Database::Virus TRDldrChepvilI3;

TRDldrChepvilI3.md5 = "3ea3867021cc7389e00c70d819fadfae";
TRDldrChepvilI3.name = "TR/Dldr.Chepvil.I.3";

if (filehash == TRDldrChepvilI3.md5)
{

return TRDldrChepvilI3.name;

}

Database::Virus TRSteamGamesB;

TRSteamGamesB.md5 = "e62c4d1919917c3dfe77b12ed41f6413";
TRSteamGamesB.name = "TR/SteamGames.B";

if (filehash == TRSteamGamesB.md5)
{

return TRSteamGamesB.name;

}

Database::Virus TRKoutodoorpsa;

TRKoutodoorpsa.md5 = "da962903b495d0ba174639b485787a53";
TRKoutodoorpsa.name = "TR/Koutodoor.psa";

if (filehash == TRKoutodoorpsa.md5)
{

return TRKoutodoorpsa.name;

}

Database::Virus TRFakeDefragA;

TRFakeDefragA.md5 = "7addd7bcf1e0e40b67930605d63fdb8a";
TRFakeDefragA.name = "TR/FakeDefrag.A";

if (filehash == TRFakeDefragA.md5)
{

return TRFakeDefragA.name;

}

Database::Virus TRJorikShakBlaOJ;

TRJorikShakBlaOJ.md5 = "b4014cee8fdf826462901617b431fae5";
TRJorikShakBlaOJ.name = "TR/Jorik.ShakBla.OJ";

if (filehash == TRJorikShakBlaOJ.md5)
{

return TRJorikShakBlaOJ.name;

}

Database::Virus TRPolyAgentC;

TRPolyAgentC.md5 = "5ecfcc3b7b7ede96a8c6636bb0daeddf";
TRPolyAgentC.name = "TR/Poly.Agent.C";

if (filehash == TRPolyAgentC.md5)
{

return TRPolyAgentC.name;

}

Database::Virus TREmuniK;

TREmuniK.md5 = "986839ced1802cfa2a38e7d2796254e4";
TREmuniK.name = "TR/Emuni.K";

if (filehash == TREmuniK.md5)
{

return TREmuniK.name;

}

Database::Virus TRPSWOnlineGamesKBRO;

TRPSWOnlineGamesKBRO.md5 = "43874a53731386129be008956d1c9756";
TRPSWOnlineGamesKBRO.name = "TR/PSW.OnlineGames.KBRO";

if (filehash == TRPSWOnlineGamesKBRO.md5)
{

return TRPSWOnlineGamesKBRO.name;

}

Database::Virus TRQhostmju53;

TRQhostmju53.md5 = "72ddf833fa206326e15c2c97679d323e";
TRQhostmju53.name = "TR/Qhost.mju.53";

if (filehash == TRQhostmju53.md5)
{

return TRQhostmju53.name;

}

Database::Virus TRHilotiA159;

TRHilotiA159.md5 = "6720149e421e2663aae2add43a1e0457";
TRHilotiA159.name = "TR/Hiloti.A.159";

if (filehash == TRHilotiA159.md5)
{

return TRHilotiA159.name;

}

Database::Virus TRPSWMaganiaI;

TRPSWMaganiaI.md5 = "ebefbaca078971eb9e0912675d7a3299";
TRPSWMaganiaI.name = "TR/PSW.Magania.I";

if (filehash == TRPSWMaganiaI.md5)
{

return TRPSWMaganiaI.name;

}

Database::Virus TRDldrNirava913;

TRDldrNirava913.md5 = "e16ea30154b0d08868cddbb54c439f06";
TRDldrNirava913.name = "TR/Dldr.Nirava.91.3";

if (filehash == TRDldrNirava913.md5)
{

return TRDldrNirava913.name;

}

Database::Virus TRBankerBankerbhvf3;

TRBankerBankerbhvf3.md5 = "d8824b4a4ec15477bc46c80c86668f7d";
TRBankerBankerbhvf3.name = "TR/Banker.Banker.bhvf.3";

if (filehash == TRBankerBankerbhvf3.md5)
{

return TRBankerBankerbhvf3.name;

}

Database::Virus TRDldrJNYJ;

TRDldrJNYJ.md5 = "d8b5ab955c42baad5cb79855781b3331";
TRDldrJNYJ.name = "TR/Dldr.JNYJ";

if (filehash == TRDldrJNYJ.md5)
{

return TRDldrJNYJ.name;

}

Database::Virus TRKillavNJ;

TRKillavNJ.md5 = "4beca2b8788ef210bfe35bd70f6ab4ac";
TRKillavNJ.name = "TR/Killav.NJ";

if (filehash == TRKillavNJ.md5)
{

return TRKillavNJ.name;

}

Database::Virus TRSpyZBotacl;

TRSpyZBotacl.md5 = "64901cfdfb576d7c7c1d4f1f240315e2";
TRSpyZBotacl.name = "TR/Spy.ZBot.acl";

if (filehash == TRSpyZBotacl.md5)
{

return TRSpyZBotacl.name;

}

Database::Virus TRGendal173568;

TRGendal173568.md5 = "101223db2dfc123b8cfe9d01e9e6c7bf";
TRGendal173568.name = "TR/Gendal.173568";

if (filehash == TRGendal173568.md5)
{

return TRGendal173568.name;

}

Database::Virus TRRimecudA1859;

TRRimecudA1859.md5 = "5d1ac261c4312106ce27fede4af939de";
TRRimecudA1859.name = "TR/Rimecud.A.1859";

if (filehash == TRRimecudA1859.md5)
{

return TRRimecudA1859.name;

}

Database::Virus TRWebprefixB14;

TRWebprefixB14.md5 = "002d1f0F3d450Db999ff95262703bb8a";
TRWebprefixB14.name = "TR/Webprefix.B.14";

if (filehash == TRWebprefixB14.md5)
{

return TRWebprefixB14.name;

}

Database::Virus TRGendal175104;

TRGendal175104.md5 = "043eadfd2eb317ea712b0b60faf0d9db";
TRGendal175104.name = "TR/Gendal.175104";

if (filehash == TRGendal175104.md5)
{

return TRGendal175104.name;

}

Database::Virus TRInject983041;

TRInject983041.md5 = "372efa98fa93a70c1edc9c621ca31dc6";
TRInject983041.name = "TR/Inject.98304.1";

if (filehash == TRInject983041.md5)
{

return TRInject983041.name;

}

Database::Virus TRCosstalzr;

TRCosstalzr.md5 = "2089b0f682a8fcd79665a9644150998b";
TRCosstalzr.name = "TR/Cossta.lzr";

if (filehash == TRCosstalzr.md5)
{

return TRCosstalzr.name;

}

Database::Virus TRDldrChepvilJ21;

TRDldrChepvilJ21.md5 = "3b7bd47d02fc57b528b0b8d96b22beed";
TRDldrChepvilJ21.name = "TR/Dldr.Chepvil.J.21";

if (filehash == TRDldrChepvilJ21.md5)
{

return TRDldrChepvilJ21.name;

}

Database::Virus TROnlinegames10821;

TROnlinegames10821.md5 = "712618CEA37312C2B544FFECD2169822";
TROnlinegames10821.name = "TR/Onlinegames.1082.1";

if (filehash == TROnlinegames10821.md5)
{

return TROnlinegames10821.name;

}

Database::Virus TRPakesola;

TRPakesola.md5 = "39651e474d7ef8d52f4f18db91b7ee56";
TRPakesola.name = "TR/Pakes.ola";

if (filehash == TRPakesola.md5)
{

return TRPakesola.name;

}

Database::Virus TRPSWMaganiaefln;

TRPSWMaganiaefln.md5 = "bc6674796fd2923d4feafa0207698a35";
TRPSWMaganiaefln.name = "TR/PSW.Magania.efln";

if (filehash == TRPSWMaganiaefln.md5)
{

return TRPSWMaganiaefln.name;

}

Database::Virus TRDldrGeralvng;

TRDldrGeralvng.md5 = "9b0c12025217508a1436683efa4faab5";
TRDldrGeralvng.name = "TR/Dldr.Geral.vng";

if (filehash == TRDldrGeralvng.md5)
{

return TRDldrGeralvng.name;

}

Database::Virus TRSpy10956814;

TRSpy10956814.md5 = "c233fc38820506102d47e03c3de4362e";
TRSpy10956814.name = "TR/Spy.109568.14";

if (filehash == TRSpy10956814.md5)
{

return TRSpy10956814.name;

}

Database::Virus TRKazymekml1;

TRKazymekml1.md5 = "01fb5950dabe777ef528d16295fba021";
TRKazymekml1.name = "TR/Kazy.mekml.1";

if (filehash == TRKazymekml1.md5)
{

return TRKazymekml1.name;

}

Database::Virus TRPSWOnlineGamesKDHG1;

TRPSWOnlineGamesKDHG1.md5 = "28c89030cbd4b4f42302f50ca07f5de2";
TRPSWOnlineGamesKDHG1.name = "TR/PSW.OnlineGames.KDHG.1";

if (filehash == TRPSWOnlineGamesKDHG1.md5)
{

return TRPSWOnlineGamesKDHG1.name;

}

Database::Virus TRSpySpyEyesegp;

TRSpySpyEyesegp.md5 = "d58a02ab8a9a9b2b6bc2a98937471b16";
TRSpySpyEyesegp.name = "TR/Spy.SpyEyes.egp";

if (filehash == TRSpySpyEyesegp.md5)
{

return TRSpySpyEyesegp.name;

}

Database::Virus TRDldrAutoItjj;

TRDldrAutoItjj.md5 = "a639de508f11e405b692c4befa0b1de0";
TRDldrAutoItjj.name = "TR/Dldr.AutoIt.jj";

if (filehash == TRDldrAutoItjj.md5)
{

return TRDldrAutoItjj.name;

}

Database::Virus TRSpyeyeK;

TRSpyeyeK.md5 = "bd03552ce976cbb5b1d01e3abad49112";
TRSpyeyeK.name = "TR/Spyeye.K";

if (filehash == TRSpyeyeK.md5)
{

return TRSpyeyeK.name;

}

Database::Virus TRSpyZBotawgq;

TRSpyZBotawgq.md5 = "8142026d807be4faedaec15bc1256fb6";
TRSpyZBotawgq.name = "TR/Spy.ZBot.awgq";

if (filehash == TRSpyZBotawgq.md5)
{

return TRSpyZBotawgq.name;

}

Database::Virus TRDropSmallgic;

TRDropSmallgic.md5 = "a8aa2d8016e798f5cdb6d45aaf338b38";
TRDropSmallgic.name = "TR/Drop.Small.gic";

if (filehash == TRDropSmallgic.md5)
{

return TRDropSmallgic.name;

}

Database::Virus TRSpySpyEyesego;

TRSpySpyEyesego.md5 = "479c784213770a6fa16c8e8bb735b622";
TRSpySpyEyesego.name = "TR/Spy.SpyEyes.ego";

if (filehash == TRSpySpyEyesego.md5)
{

return TRSpySpyEyesego.name;

}

Database::Virus TRDldrInjecterfou;

TRDldrInjecterfou.md5 = "0Ea791a344014661db8e2b0F5ab00B91";
TRDldrInjecterfou.name = "TR/Dldr.Injecter.fou";

if (filehash == TRDldrInjecterfou.md5)
{

return TRDldrInjecterfou.name;

}

Database::Virus TRDldrChepvilJ19;

TRDldrChepvilJ19.md5 = "bb01aaa72b230483d0db72e92cb3e07b";
TRDldrChepvilJ19.name = "TR/Dldr.Chepvil.J.19";

if (filehash == TRDldrChepvilJ19.md5)
{

return TRDldrChepvilJ19.name;

}

Database::Virus TRKazy178296;

TRKazy178296.md5 = "265d4ec7fd799990cc4084d5b8876c84";
TRKazy178296.name = "TR/Kazy.17829.6";

if (filehash == TRKazy178296.md5)
{

return TRKazy178296.name;

}

Database::Virus TRMSILDelFilesabg;

TRMSILDelFilesabg.md5 = "5f119a26a6d59aebdb74b375de965b2a";
TRMSILDelFilesabg.name = "TR/MSIL.DelFiles.abg";

if (filehash == TRMSILDelFilesabg.md5)
{

return TRMSILDelFilesabg.name;

}

Database::Virus TRGendal157184;

TRGendal157184.md5 = "e7e708e3d5ae6c823f60655474140500";
TRGendal157184.name = "TR/Gendal.157184";

if (filehash == TRGendal157184.md5)
{

return TRGendal157184.name;

}

Database::Virus TRKazy892928;

TRKazy892928.md5 = "45605afcb319247dfd7ccc17d909cff1";
TRKazy892928.name = "TR/Kazy.892928";

if (filehash == TRKazy892928.md5)
{

return TRKazy892928.name;

}

Database::Virus TRRamnitA22;

TRRamnitA22.md5 = "b8639c44126fb50de80354b95fad0153";
TRRamnitA22.name = "TR/Ramnit.A.22";

if (filehash == TRRamnitA22.md5)
{

return TRRamnitA22.name;

}

Database::Virus TRFakeAVacad;

TRFakeAVacad.md5 = "d6faf1ad833c9405b1e48cb0e62074ca";
TRFakeAVacad.name = "TR/FakeAV.acad";

if (filehash == TRFakeAVacad.md5)
{

return TRFakeAVacad.name;

}

Database::Virus TRDldrAgentgdnb;

TRDldrAgentgdnb.md5 = "82035cbeff1cba0Efd42f8791e46888d";
TRDldrAgentgdnb.name = "TR/Dldr.Agent.gdnb";

if (filehash == TRDldrAgentgdnb.md5)
{

return TRDldrAgentgdnb.name;

}

Database::Virus TRZbot836;

TRZbot836.md5 = "202a068e9e52853d7ed7887ec7dfbe52";
TRZbot836.name = "TR/Zbot.836";

if (filehash == TRZbot836.md5)
{

return TRZbot836.name;

}

Database::Virus TRFakeAvacz;

TRFakeAvacz.md5 = "67157809ae3052a511011865127def56";
TRFakeAvacz.name = "TR/FakeAv.acz";

if (filehash == TRFakeAvacz.md5)
{

return TRFakeAvacz.name;

}

Database::Virus TRCalelkC;

TRCalelkC.md5 = "3d69cd92cc7d2c76471600d1f4a8546c";
TRCalelkC.name = "TR/Calelk.C";

if (filehash == TRCalelkC.md5)
{

return TRCalelkC.name;

}

Database::Virus TRAgent192512A;

TRAgent192512A.md5 = "13a8c59530b167823aaf7254eaed6125";
TRAgent192512A.name = "TR/Agent.192512.A";

if (filehash == TRAgent192512A.md5)
{

return TRAgent192512A.name;

}

Database::Virus TRGendal1745921;

TRGendal1745921.md5 = "bd68cc65b16e9badaddb4d109124a52d";
TRGendal1745921.name = "TR/Gendal.174592.1";

if (filehash == TRGendal1745921.md5)
{

return TRGendal1745921.name;

}

Database::Virus TRVBaqt1;

TRVBaqt1.md5 = "83bbe8eb6a438720551053ef9dc29728";
TRVBaqt1.name = "TR/VB.aqt.1";

if (filehash == TRVBaqt1.md5)
{

return TRVBaqt1.name;

}

Database::Virus TRPSWMaganiadlna;

TRPSWMaganiadlna.md5 = "e8cf038dd527b62048935aa20de8ba73";
TRPSWMaganiadlna.name = "TR/PSW.Magania.dlna";

if (filehash == TRPSWMaganiadlna.md5)
{

return TRPSWMaganiadlna.name;

}

Database::Virus TRAgentaeim;

TRAgentaeim.md5 = "385323ccdc790b3302b32120ef1dbe9a";
TRAgentaeim.name = "TR/Agent.aeim";

if (filehash == TRAgentaeim.md5)
{

return TRAgentaeim.name;

}

Database::Virus TRGendal158208;

TRGendal158208.md5 = "67E39A4CE376C13AEABE53071465FD9A";
TRGendal158208.name = "TR/Gendal.158208";

if (filehash == TRGendal158208.md5)
{

return TRGendal158208.name;

}

Database::Virus TRVBQF;

TRVBQF.md5 = "dd82421a6535722ed7cbf23538c31573";
TRVBQF.name = "TR/VB.QF";

if (filehash == TRVBQF.md5)
{

return TRVBQF.name;

}

Database::Virus TRGendal197387;

TRGendal197387.md5 = "5DA95412A10221C2B72803CB1EC69557";
TRGendal197387.name = "TR/Gendal.197387";

if (filehash == TRGendal197387.md5)
{

return TRGendal197387.name;

}

Database::Virus TRFakeAlertNS;

TRFakeAlertNS.md5 = "69e81b74f2a8e74c058bc4846c602191";
TRFakeAlertNS.name = "TR/FakeAlert.NS";

if (filehash == TRFakeAlertNS.md5)
{

return TRFakeAlertNS.name;

}

Database::Virus TRAutorun20828;

TRAutorun20828.md5 = "327f259a5c429e347bff319b7d6bcc53";
TRAutorun20828.name = "TR/Autorun.20828";

if (filehash == TRAutorun20828.md5)
{

return TRAutorun20828.name;

}

Database::Virus TRGendal197659;

TRGendal197659.md5 = "27f112ea6ccb3401343ebd91b8aaec21";
TRGendal197659.name = "TR/Gendal.197659";

if (filehash == TRGendal197659.md5)
{

return TRGendal197659.name;

}

Database::Virus TRAgent757768;

TRAgent757768.md5 = "2fa48a277ed630e0c2d76b7b47c3a935";
TRAgent757768.name = "TR/Agent.75776.8";

if (filehash == TRAgent757768.md5)
{

return TRAgent757768.name;

}

Database::Virus TRAgentb19;

TRAgentb19.md5 = "1b79b49ebed106374f1aac267131fe5a";
TRAgentb19.name = "TR/Agent.b.19";

if (filehash == TRAgentb19.md5)
{

return TRAgentb19.name;

}

Database::Virus TRGendal239616;

TRGendal239616.md5 = "1660fdf84ee6bdec895ce8f421e30561";
TRGendal239616.name = "TR/Gendal.239616";

if (filehash == TRGendal239616.md5)
{

return TRGendal239616.name;

}

Database::Virus TRKazyT2;

TRKazyT2.md5 = "185f95afde2edab49b26a748c4bcb0a9";
TRKazyT2.name = "TR/Kazy.T.2";

if (filehash == TRKazyT2.md5)
{

return TRKazyT2.name;

}

Database::Virus TRKoobfaceA1;

TRKoobfaceA1.md5 = "f072b6c11a365f998c492009863ab0a3";
TRKoobfaceA1.name = "TR/Koobface.A.1";

if (filehash == TRKoobfaceA1.md5)
{

return TRKoobfaceA1.name;

}

Database::Virus TRPSWMaganiadkqp;

TRPSWMaganiadkqp.md5 = "3bd1e56b714d0d75bf90bd0021c92514";
TRPSWMaganiadkqp.name = "TR/PSW.Magania.dkqp";

if (filehash == TRPSWMaganiadkqp.md5)
{

return TRPSWMaganiadkqp.name;

}

Database::Virus TRDldrHarnigS210;

TRDldrHarnigS210.md5 = "ddb10abd15846eb81f2c973ed4cd6f14";
TRDldrHarnigS210.name = "TR/Dldr.Harnig.S.210";

if (filehash == TRDldrHarnigS210.md5)
{

return TRDldrHarnigS210.name;

}

Database::Malware TRDldrPinchLordC;

TRDldrPinchLordC.md5 = "88a43680ca07bd4ecab6cfe2c0c1fea7";
TRDldrPinchLordC.name = "TR/Dldr.PinchLord.C";

if (filehash == TRDldrPinchLordC.md5)
{

return TRDldrPinchLordC.name;

}

Database::Malware TRPSWPaprasA2;

TRPSWPaprasA2.md5 = "7db7070b44405cd8bedbe8fe7acf3c80";
TRPSWPaprasA2.name = "TR/PSW.Papras.A.2";

if (filehash == TRPSWPaprasA2.md5)
{

return TRPSWPaprasA2.name;

}

Database::Malware TRGendal200704;

TRGendal200704.md5 = "e93e9cfdfdd8953acd171acdbeaa49c4";
TRGendal200704.name = "TR/Gendal.200704";

if (filehash == TRGendal200704.md5)
{

return TRGendal200704.name;

}

Database::Malware TRSpyZBot2536;

TRSpyZBot2536.md5 = "94273b9ab6358d7b1ba6bf04b3d6a330";
TRSpyZBot2536.name = "TR/Spy.ZBot.25.36";

if (filehash == TRSpyZBot2536.md5)
{

return TRSpyZBot2536.name;

}

Database::Virus TRDropSmallfvz;

TRDropSmallfvz.md5 = "fbc55416c2e991434e63e1a7398f1be0";
TRDropSmallfvz.name = "TR/Drop.Small.fvz";

if (filehash == TRDropSmallfvz.md5)
{

return TRDropSmallfvz.name;

}

Database::Virus TRInjectorEK;

TRInjectorEK.md5 = "9D4EF42CDDC4E975B05C2F3F6235129E";
TRInjectorEK.name = "TR/Injector.EK";

if (filehash == TRInjectorEK.md5)
{

return TRInjectorEK.name;

}

Database::Virus TRPincavagbu;

TRPincavagbu.md5 = "20db8ec7b7abc52e4cf522799223b23e";
TRPincavagbu.name = "TR/Pincav.agbu";

if (filehash == TRPincavagbu.md5)
{

return TRPincavagbu.name;

}

Database::Virus TRMeredropA5572;

TRMeredropA5572.md5 = "3F6D39366424F16562CA9B6873B580BD";
TRMeredropA5572.name = "TR/Meredrop.A.5572";

if (filehash == TRMeredropA5572.md5)
{

return TRMeredropA5572.name;

}

Database::Virus TRDldrAgentesbl;

TRDldrAgentesbl.md5 = "5e50aeac80340ea2990858fd74b76061";
TRDldrAgentesbl.name = "TR/Dldr.Agent.esbl";

if (filehash == TRDldrAgentesbl.md5)
{

return TRDldrAgentesbl.name;

}

Database::Virus TRVBKrypteei;

TRVBKrypteei.md5 = "3d27365600909fd7899524672fd4d182";
TRVBKrypteei.name = "TR/VBKrypt.eei";

if (filehash == TRVBKrypteei.md5)
{

return TRVBKrypteei.name;

}

Database::Virus TRPSWMaganiaauuk;

TRPSWMaganiaauuk.md5 = "afb5c50bb0cefc3966a4fd78b4eabc9d";
TRPSWMaganiaauuk.name = "TR/PSW.Magania.auuk";

if (filehash == TRPSWMaganiaauuk.md5)
{

return TRPSWMaganiaauuk.name;

}

Database::Virus TRPSWAgenttyy;

TRPSWAgenttyy.md5 = "b98fa3b4949c155aa893a7485b76578d";
TRPSWAgenttyy.name = "TR/PSW.Agent.tyy";

if (filehash == TRPSWAgenttyy.md5)
{

return TRPSWAgenttyy.name;

}

Database::Virus TRAgentb21;

TRAgentb21.md5 = "e6e785ed44156032c4de992f3feb4c2d";
TRAgentb21.name = "TR/Agent.b.21";

if (filehash == TRAgentb21.md5)
{

return TRAgentb21.name;

}

Database::Virus TRAgentb20;

TRAgentb20.md5 = "5775dbfd14cccd5fff8d90ff94257d4f";
TRAgentb20.name = "TR/Agent.b.20";

if (filehash == TRAgentb20.md5)
{

return TRAgentb20.name;

}

Database::Virus TROnlineGam92661;

TROnlineGam92661.md5 = "08d43885f798e6a7f3d7a6eeb0ad67ce";
TROnlineGam92661.name = "TR/OnlineGam.92661";

if (filehash == TROnlineGam92661.md5)
{

return TROnlineGam92661.name;

}

Database::Virus TRAgentb4;

TRAgentb4.md5 = "4a5d8e9b513d5446403400a0131a8273";
TRAgentb4.name = "TR/Agent.b.4";

if (filehash == TRAgentb4.md5)
{

return TRAgentb4.name;

}

Database::Virus TRIrcbruteA941;

TRIrcbruteA941.md5 = "1F8CD13341245588FC97E8F05C551E7E";
TRIrcbruteA941.name = "TR/Ircbrute.A.941";

if (filehash == TRIrcbruteA941.md5)
{

return TRIrcbruteA941.name;

}

Database::Virus TRDldrRenosLX677;

TRDldrRenosLX677.md5 = "EE04BD7FD1D45ED35AD76154C34F416F";
TRDldrRenosLX677.name = "TR/Dldr.Renos.LX.677";

if (filehash == TRDldrRenosLX677.md5)
{

return TRDldrRenosLX677.name;

}

Database::Virus TRPSWMaganiadkee;

TRPSWMaganiadkee.md5 = "f9e6b9d456e5f918c3e3f1dd91839314";
TRPSWMaganiadkee.name = "TR/PSW.Magania.dkee";

if (filehash == TRPSWMaganiadkee.md5)
{

return TRPSWMaganiadkee.name;

}

Database::Virus TRPSWMaganiadmgc;

TRPSWMaganiadmgc.md5 = "8857a12bc88489b995912f46c1307b9b";
TRPSWMaganiadmgc.name = "TR/PSW.Magania.dmgc";

if (filehash == TRPSWMaganiadmgc.md5)
{

return TRPSWMaganiadmgc.name;

}

Database::Virus TRPSWMaganiadqoc;

TRPSWMaganiadqoc.md5 = "df26560ee559155b14bcb28b8ff77614";
TRPSWMaganiadqoc.name = "TR/PSW.Magania.dqoc";

if (filehash == TRPSWMaganiadqoc.md5)
{

return TRPSWMaganiadqoc.name;

}

Database::Virus TRAgentqwr;

TRAgentqwr.md5 = "1E3066B7E6960505F567D28A529DDBA8";
TRAgentqwr.name = "TR/Agent.qwr";

if (filehash == TRAgentqwr.md5)
{

return TRAgentqwr.name;

}

Database::Virus TRPSWMaganiadhcw;

TRPSWMaganiadhcw.md5 = "bf9a1cb46bb61362ae268c1725661f7f";
TRPSWMaganiadhcw.name = "TR/PSW.Magania.dhcw";

if (filehash == TRPSWMaganiadhcw.md5)
{

return TRPSWMaganiadhcw.name;

}

Database::Virus TRPSWMaganiadkiq;

TRPSWMaganiadkiq.md5 = "094ff3b924254e0f161c818ea43a6f0a";
TRPSWMaganiadkiq.name = "TR/PSW.Magania.dkiq";

if (filehash == TRPSWMaganiadkiq.md5)
{

return TRPSWMaganiadkiq.name;

}

Database::Virus TRSpy53248681;

TRSpy53248681.md5 = "1C886EABF2D5A89329CA4529DFA6BB21";
TRSpy53248681.name = "TR/Spy.53248.681";

if (filehash == TRSpy53248681.md5)
{

return TRSpy53248681.name;

}

Database::Virus TRSpyZBotIE3;

TRSpyZBotIE3.md5 = "d4d7655ee338c61021bd8d1f03d4605f";
TRSpyZBotIE3.name = "TR/Spy.ZBot.IE.3";

if (filehash == TRSpyZBotIE3.md5)
{

return TRSpyZBotIE3.name;

}

Database::Virus TRDropVBBAK;

TRDropVBBAK.md5 = "6f638a6d41d60c969946e75b7c020018";
TRDropVBBAK.name = "TR/Drop.VB.BAK";

if (filehash == TRDropVBBAK.md5)
{

return TRDropVBBAK.name;

}

Database::Virus TRDldrAgentA5;

TRDldrAgentA5.md5 = "B22EF26B830600B47A3FEA87ADCFF91C";
TRDldrAgentA5.name = "TR/Dldr.Agent.A.5";

if (filehash == TRDldrAgentA5.md5)
{

return TRDldrAgentA5.name;

}

Database::Virus TRVBKryptgbr;

TRVBKryptgbr.md5 = "05ac465e7d76ddc0480b54e158dd2852";
TRVBKryptgbr.name = "TR/VBKrypt.gbr";

if (filehash == TRVBKryptgbr.md5)
{

return TRVBKryptgbr.name;

}

Database::Virus TRMeredropA15466;

TRMeredropA15466.md5 = "c4d499bc672aff08023aadee3ae5d6be";
TRMeredropA15466.name = "TR/Meredrop.A.15466";

if (filehash == TRMeredropA15466.md5)
{

return TRMeredropA15466.name;

}

Database::Virus TRKazy23592;

TRKazy23592.md5 = "e33606fe1d073b6fd2f7f1a9c83eace7";
TRKazy23592.name = "TR/Kazy.2359.2";

if (filehash == TRKazy23592.md5)
{

return TRKazy23592.name;

}

Database::Virus TRKazy23591;

TRKazy23591.md5 = "db21667739a4b0bf484093abc359c167";
TRKazy23591.name = "TR/Kazy.2359.1";

if (filehash == TRKazy23591.md5)
{

return TRKazy23591.name;

}

Database::Virus TRInjectorBH;

TRInjectorBH.md5 = "748610496089bcb82b95fe67062f314c";
TRInjectorBH.name = "TR/Injector.BH";

if (filehash == TRInjectorBH.md5)
{

return TRInjectorBH.name;

}

Database::Virus TRKryptikNC1;

TRKryptikNC1.md5 = "3892771CC3C0F2B723A9FBA2A0EA6D41";
TRKryptikNC1.name = "TR/Kryptik.NC.1";

if (filehash == TRKryptikNC1.md5)
{

return TRKryptikNC1.name;

}

Database::Virus TRPSWOnlineGamesKDGK;

TRPSWOnlineGamesKDGK.md5 = "b245e6467b9b9364cb9f1bf24d2496f2";
TRPSWOnlineGamesKDGK.name = "TR/PSW.OnlineGames.KDGK";

if (filehash == TRPSWOnlineGamesKDGK.md5)
{

return TRPSWOnlineGamesKDGK.name;

}

Database::Virus TROnLineGame90816;

TROnLineGame90816.md5 = "a50E0A34cbbd175209338cce426413b2";
TROnLineGame90816.name = "TR/OnLineGame.90816";

if (filehash == TROnLineGame90816.md5)
{

return TROnLineGame90816.name;

}

Database::Virus TRAgentcqx1;

TRAgentcqx1.md5 = "5FEA6B4DCFA84224A48FE95E572B2B85";
TRAgentcqx1.name = "TR/Agent.cqx.1";

if (filehash == TRAgentcqx1.md5)
{

return TRAgentcqx1.name;

}

Database::Virus TRKazy2388;

TRKazy2388.md5 = "9fe878223c6920674106de0d6cc69f75";
TRKazy2388.name = "TR/Kazy.2388";

if (filehash == TRKazy2388.md5)
{

return TRKazy2388.name;

}

Database::Virus TRAgentARHD15;

TRAgentARHD15.md5 = "e433e1a3fd09fd0D3925b0579b3a4583";
TRAgentARHD15.name = "TR/Agent.ARHD.15";

if (filehash == TRAgentARHD15.md5)
{

return TRAgentARHD15.name;

}

Database::Virus TRDldrFraudLoadhdq;

TRDldrFraudLoadhdq.md5 = "8c219fc61706fbe834836b0eaaaa50c9";
TRDldrFraudLoadhdq.name = "TR/Dldr.FraudLoad.hdq";

if (filehash == TRDldrFraudLoadhdq.md5)
{

return TRDldrFraudLoadhdq.name;

}

Database::Virus TRKazy20303;

TRKazy20303.md5 = "6199E3053EE821CC33B8FDE8CD3CAFD8";
TRKazy20303.name = "TR/Kazy.2030.3";

if (filehash == TRKazy20303.md5)
{

return TRKazy20303.name;

}

Database::Virus TRInjectorCsa1;

TRInjectorCsa1.md5 = "496cab30c18ae76fb775386a2853e037";
TRInjectorCsa1.name = "TR/Injector.Csa.1";

if (filehash == TRInjectorCsa1.md5)
{

return TRInjectorCsa1.name;

}

Database::Virus TRKazy1438;

TRKazy1438.md5 = "7120b7da4b01c4cf262f8c0b32422d96";
TRKazy1438.name = "TR/Kazy.1438";

if (filehash == TRKazy1438.md5)
{

return TRKazy1438.name;

}

Database::Virus TRPSWMaganiadmox;

TRPSWMaganiadmox.md5 = "3bb0ce6249f50f9db051e5260cfa43aa";
TRPSWMaganiadmox.name = "TR/PSW.Magania.dmox";

if (filehash == TRPSWMaganiadmox.md5)
{

return TRPSWMaganiadmox.name;

}

Database::Virus TRPSWMaganiadmkp;

TRPSWMaganiadmkp.md5 = "307092138dc36d955fab4bcc150640a0";
TRPSWMaganiadmkp.name = "TR/PSW.Magania.dmkp";

if (filehash == TRPSWMaganiadmkp.md5)
{

return TRPSWMaganiadmkp.name;

}

Database::Virus TRPSWMaganiadmdf;

TRPSWMaganiadmdf.md5 = "2bf3cdb6faf2448b06072387a6c714e9";
TRPSWMaganiadmdf.name = "TR/PSW.Magania.dmdf";

if (filehash == TRPSWMaganiadmdf.md5)
{

return TRPSWMaganiadmdf.name;

}

Database::Virus TRKazy2374;

TRKazy2374.md5 = "3f4a74bf4d5a177c5987de893e2ada78";
TRKazy2374.name = "TR/Kazy.2374";

if (filehash == TRKazy2374.md5)
{

return TRKazy2374.name;

}

Database::Virus TRPSWMaganiadlvc;

TRPSWMaganiadlvc.md5 = "015389289c1a65d44264b8f867c13f02";
TRPSWMaganiadlvc.name = "TR/PSW.Magania.dlvc";

if (filehash == TRPSWMaganiadlvc.md5)
{

return TRPSWMaganiadlvc.name;

}

Database::Virus TRPSWMaganiadiiy;

TRPSWMaganiadiiy.md5 = "fb313deb0419afd69b064eb99459e030";
TRPSWMaganiadiiy.name = "TR/PSW.Magania.diiy";

if (filehash == TRPSWMaganiadiiy.md5)
{

return TRPSWMaganiadiiy.name;

}

Database::Virus TRSpy53760147;

TRSpy53760147.md5 = "9afdd3c9ab12d8bfe45d046d150bd47c";
TRSpy53760147.name = "TR/Spy.53760.147";

if (filehash == TRSpy53760147.md5)
{

return TRSpy53760147.name;

}

Database::Virus TRPSWMaganiadknk;

TRPSWMaganiadknk.md5 = "d16b1519949cf020d44b5364a3a23685";
TRPSWMaganiadknk.name = "TR/PSW.Magania.dknk";

if (filehash == TRPSWMaganiadknk.md5)
{

return TRPSWMaganiadknk.name;

}

Database::Virus TRDropSmallfwj;

TRDropSmallfwj.md5 = "ca94435dce71606f9107d42913fe5d75";
TRDropSmallfwj.name = "TR/Drop.Small.fwj";

if (filehash == TRDropSmallfwj.md5)
{

return TRDropSmallfwj.name;

}

Database::Virus TRPSWMaganiadkcd;

TRPSWMaganiadkcd.md5 = "d197c744ba57ef3a5cc4a059b8800901";
TRPSWMaganiadkcd.name = "TR/PSW.Magania.dkcd";

if (filehash == TRPSWMaganiadkcd.md5)
{

return TRPSWMaganiadkcd.name;

}

Database::Virus TRPSWMaganiadbjr;

TRPSWMaganiadbjr.md5 = "c6eea61d2f6c5d51a84a5fe0b65d59eb";
TRPSWMaganiadbjr.name = "TR/PSW.Magania.dbjr";

if (filehash == TRPSWMaganiadbjr.md5)
{

return TRPSWMaganiadbjr.name;

}

Database::Virus TRPSWMaganiadhyv;

TRPSWMaganiadhyv.md5 = "5c87d9891460aaf402bc591cd5d3f94d";
TRPSWMaganiadhyv.name = "TR/PSW.Magania.dhyv";

if (filehash == TRPSWMaganiadhyv.md5)
{

return TRPSWMaganiadhyv.name;

}

Database::Virus TRPSWMaganiadlun;

TRPSWMaganiadlun.md5 = "0b4919f2431d5b9a2c7a348bddfd8bc2";
TRPSWMaganiadlun.name = "TR/PSW.Magania.dlun";

if (filehash == TRPSWMaganiadlun.md5)
{

return TRPSWMaganiadlun.name;

}

Database::Virus TRGendal109568;

TRGendal109568.md5 = "f5fa1f6ed4dabca833e2450e4ab70f18";
TRGendal109568.name = "TR/Gendal.109568";

if (filehash == TRGendal109568.md5)
{

return TRGendal109568.name;

}

Database::Virus TRPSWMaganiadjdg;

TRPSWMaganiadjdg.md5 = "08fd5a087007cedf3af1194a79df3644";
TRPSWMaganiadjdg.name = "TR/PSW.Magania.djdg";

if (filehash == TRPSWMaganiadjdg.md5)
{

return TRPSWMaganiadjdg.name;

}

Database::Virus TRKazy2359;

TRKazy2359.md5 = "749fd4d1caa3f7038e69121a94a9af0f";
TRKazy2359.name = "TR/Kazy.2359";

if (filehash == TRKazy2359.md5)
{

return TRKazy2359.name;

}

Database::Virus TRSpy571448;

TRSpy571448.md5 = "e566035629df2f996fd25f6d6eb47377";
TRSpy571448.name = "TR/Spy.571448";

if (filehash == TRSpy571448.md5)
{

return TRSpy571448.name;

}

Database::Virus TRSpy12625924;

TRSpy12625924.md5 = "9f798355fdf4d0b5bd5711333da46c3d";
TRSpy12625924.name = "TR/Spy.1262592.4";

if (filehash == TRSpy12625924.md5)
{

return TRSpy12625924.name;

}

Database::Virus TRSpyZBotHB;

TRSpyZBotHB.md5 = "ca740afab1bc3a6b884d8f40506a7da8";
TRSpyZBotHB.name = "TR/Spy.ZBot.HB";

if (filehash == TRSpyZBotHB.md5)
{

return TRSpyZBotHB.name;

}

Database::Virus TRKazy3450;

TRKazy3450.md5 = "34e36e1f5f26970c5c6322f48892b9d0";
TRKazy3450.name = "TR/Kazy.3450";

if (filehash == TRKazy3450.md5)
{

return TRKazy3450.name;

}

Database::Virus TRSpySpyEyeseic;

TRSpySpyEyeseic.md5 = "a17ee10abdaf0c5c34abb551dab340b5";
TRSpySpyEyeseic.name = "TR/Spy.SpyEyes.eic";

if (filehash == TRSpySpyEyeseic.md5)
{

return TRSpySpyEyeseic.name;

}

Database::Virus TRDropAgenttzb;

TRDropAgenttzb.md5 = "46d5d944e89a3584f20583b3f2de51cb";
TRDropAgenttzb.name = "TR/Drop.Agent.tzb";

if (filehash == TRDropAgenttzb.md5)
{

return TRDropAgenttzb.name;

}

Database::Virus TRSpyZBotanhk1;

TRSpyZBotanhk1.md5 = "2a99d961d3b9be0b20022d50d06509ce";
TRSpyZBotanhk1.name = "TR/Spy.ZBot.anhk.1";

if (filehash == TRSpyZBotanhk1.md5)
{

return TRSpyZBotanhk1.name;

}

Database::Virus TRDldrRenospsx22;

TRDldrRenospsx22.md5 = "1f06f8334681f58c2f9339e7ab3b3265";
TRDldrRenospsx22.name = "TR/Dldr.Renos.psx.22";

if (filehash == TRDldrRenospsx22.md5)
{

return TRDldrRenospsx22.name;

}

Database::Virus TRLlacglr;

TRLlacglr.md5 = "547e54bca5cd95b89b86eedc21fc5dc9";
TRLlacglr.name = "TR/Llac.glr";

if (filehash == TRLlacglr.md5)
{

return TRLlacglr.name;

}

Database::Virus TRGendal192512;

TRGendal192512.md5 = "83C749732492B43F6EFC1687BE2C8336";
TRGendal192512.name = "TR/Gendal.192512";

if (filehash == TRGendal192512.md5)
{

return TRGendal192512.name;

}

Database::Virus TRAgent8789;

TRAgent8789.md5 = "77a31b24e8af16ea374ab06e7d2c1ba7";
TRAgent8789.name = "TR/Agent.8789";

if (filehash == TRAgent8789.md5)
{

return TRAgent8789.name;

}

Database::Virus TRLlachgq;

TRLlachgq.md5 = "3d349965ff4a615ab3a7884ce8dbd0bf";
TRLlachgq.name = "TR/Llac.hgq";

if (filehash == TRLlachgq.md5)
{

return TRLlachgq.name;

}

Database::Virus TRAgentayp;

TRAgentayp.md5 = "fc69e6109e881ea62b98b68597033b86";
TRAgentayp.name = "TR/Agent.ayp";

if (filehash == TRAgentayp.md5)
{

return TRAgentayp.name;

}

Database::Virus TREyeStyeH89;

TREyeStyeH89.md5 = "3500BFB90DB9D500B9E73929E0EBDE27";
TREyeStyeH89.name = "TR/EyeStye.H.89";

if (filehash == TREyeStyeH89.md5)
{

return TREyeStyeH89.name;

}

Database::Virus TRVBdxva;

TRVBdxva.md5 = "5d798d4bd949655122f33f20bc7e3b25";
TRVBdxva.name = "TR/VB.dxva";

if (filehash == TRVBdxva.md5)
{

return TRVBdxva.name;

}

Database::Virus TRDldrCarberpC40;

TRDldrCarberpC40.md5 = "B98DCA9D1026671E202A5B260FE5EE3D";
TRDldrCarberpC40.name = "TR/Dldr.Carberp.C.40";

if (filehash == TRDldrCarberpC40.md5)
{

return TRDldrCarberpC40.name;

}

Database::Virus TRSpyZBotHT4;

TRSpyZBotHT4.md5 = "2ad828135b8619dab054d841a29fd80e";
TRSpyZBotHT4.name = "TR/Spy.ZBot.HT.4";

if (filehash == TRSpyZBotHT4.md5)
{

return TRSpyZBotHT4.name;

}

Database::Virus TRSpy18995244;

TRSpy18995244.md5 = "ee23861b6c4f5825e2a73c08c213fdf9";
TRSpy18995244.name = "TR/Spy.189952.44";

if (filehash == TRSpy18995244.md5)
{

return TRSpy18995244.name;

}

Database::Virus TRXupiA;

TRXupiA.md5 = "70022824c65233aa0F697c38ca563d3e";
TRXupiA.name = "TR/Xupi.A";

if (filehash == TRXupiA.md5)
{

return TRXupiA.name;

}

Database::Virus TRHilotiA6;

TRHilotiA6.md5 = "c9c30A1981a9220Dbe1c3a03d74c8289";
TRHilotiA6.name = "TR/Hiloti.A.6";

if (filehash == TRHilotiA6.md5)
{

return TRHilotiA6.name;

}

Database::Virus TRSpy4469766;

TRSpy4469766.md5 = "f9a3954a6ad75e6633feabee25391a83";
TRSpy4469766.name = "TR/Spy.446976.6";

if (filehash == TRSpy4469766.md5)
{

return TRSpy4469766.name;

}

Database::Virus TRZlob214950;

TRZlob214950.md5 = "2ee076be49db3a35b26654a78f9bba1e";
TRZlob214950.name = "TR/Zlob.2.14950";

if (filehash == TRZlob214950.md5)
{

return TRZlob214950.name;

}

Database::Virus TRAgentb17;

TRAgentb17.md5 = "0a7759abaa90f34a6a4ab00bb747888c";
TRAgentb17.name = "TR/Agent.b.17";

if (filehash == TRAgentb17.md5)
{

return TRAgentb17.name;

}

Database::Virus TRPSWMaganiaH;

TRPSWMaganiaH.md5 = "c4cf5acfb725cfe25da34e2f757ff5ac";
TRPSWMaganiaH.name = "TR/PSW.Magania.H";

if (filehash == TRPSWMaganiaH.md5)
{

return TRPSWMaganiaH.name;

}

Database::Virus TRIRCBotB;

TRIRCBotB.md5 = "100217ba6f4ad52cb8ffb4a5a4f53875";
TRIRCBotB.name = "TR/IRCBot.B";

if (filehash == TRIRCBotB.md5)
{

return TRIRCBotB.name;

}

Database::Virus TRSpy8601664;

TRSpy8601664.md5 = "3E96BABDBFF35689C4FEC195FE30A661";
TRSpy8601664.name = "TR/Spy.86016.64";

if (filehash == TRSpy8601664.md5)
{

return TRSpy8601664.name;

}

Database::Virus TROrsamA127;

TROrsamA127.md5 = "44327c1ed8b0507286885683544108b0";
TROrsamA127.name = "TR/Orsam.A.127";

if (filehash == TROrsamA127.md5)
{

return TROrsamA127.name;

}

Database::Virus TRSwisynC;

TRSwisynC.md5 = "5296a67c6b5c84153edef96087a2d60c";
TRSwisynC.name = "TR/Swisyn.C";

if (filehash == TRSwisynC.md5)
{

return TRSwisynC.name;

}

Database::Virus TRPSWAgenttzl;

TRPSWAgenttzl.md5 = "5b654aa748471034cad5eada878e50cd";
TRPSWAgenttzl.name = "TR/PSW.Agent.tzl";

if (filehash == TRPSWAgenttzl.md5)
{

return TRPSWAgenttzl.name;

}

Database::Virus TRRansomPornoBlockerecr;

TRRansomPornoBlockerecr.md5 = "07265879DBAC9C7C665B34EAEE0F6E50";
TRRansomPornoBlockerecr.name = "TR/Ransom.PornoBlocker.ecr";

if (filehash == TRRansomPornoBlockerecr.md5)
{

return TRRansomPornoBlockerecr.name;

}

Database::Virus TRRansomPornoBlockerang;

TRRansomPornoBlockerang.md5 = "2dcdbbf8bc72c734bd763fa06b1aac69";
TRRansomPornoBlockerang.name = "TR/Ransom.PornoBlocker.ang";

if (filehash == TRRansomPornoBlockerang.md5)
{

return TRRansomPornoBlockerang.name;

}

Database::Virus TRAgentawj;

TRAgentawj.md5 = "3daef51276503ef2a407f3ee06027d6d";
TRAgentawj.name = "TR/Agent.awj";

if (filehash == TRAgentawj.md5)
{

return TRAgentawj.name;

}

Database::Virus TRJorikPoeBots;

TRJorikPoeBots.md5 = "2b40f52664bda0565f6c2c6016c50cad";
TRJorikPoeBots.name = "TR/Jorik.PoeBot.s";

if (filehash == TRJorikPoeBots.md5)
{

return TRJorikPoeBots.name;

}

Database::Virus TRVBajia;

TRVBajia.md5 = "29da42bcdf3f09790962337e30e56135";
TRVBajia.name = "TR/VB.ajia";

if (filehash == TRVBajia.md5)
{

return TRVBajia.name;

}

Database::Virus TRVBaioi;

TRVBaioi.md5 = "007a81d8d5dc00b15e88adfd4b948cdb";
TRVBaioi.name = "TR/VB.aioi";

if (filehash == TRVBaioi.md5)
{

return TRVBaioi.name;

}

Database::Virus TRVBaiii;

TRVBaiii.md5 = "9dd4efb70a087c4358ba72d9476a238b";
TRVBaiii.name = "TR/VB.aiii";

if (filehash == TRVBaiii.md5)
{

return TRVBaiii.name;

}

Database::Virus TRAgentAV55296;

TRAgentAV55296.md5 = "4b3dcffbec9df40120ecf005928a97f7";
TRAgentAV55296.name = "TR/Agent.AV.55296";

if (filehash == TRAgentAV55296.md5)
{

return TRAgentAV55296.name;

}

Database::Virus TRSpy3077121;

TRSpy3077121.md5 = "8FC4334B769BE63BFE0171E32E01C1B7";
TRSpy3077121.name = "TR/Spy.307712.1";

if (filehash == TRSpy3077121.md5)
{

return TRSpy3077121.name;

}

Database::Virus TRAgentaqlt3;

TRAgentaqlt3.md5 = "3de40bad3d1409376ad77077159707bb";
TRAgentaqlt3.name = "TR/Agent.aqlt.3";

if (filehash == TRAgentaqlt3.md5)
{

return TRAgentaqlt3.name;

}

Database::Virus TRSpyAgentbjfd;

TRSpyAgentbjfd.md5 = "635702d2aa06886bac9be600184e9682";
TRSpyAgentbjfd.name = "TR/Spy.Agent.bjfd";

if (filehash == TRSpyAgentbjfd.md5)
{

return TRSpyAgentbjfd.name;

}

Database::Virus TRRimecudA613;

TRRimecudA613.md5 = "30A64FB6EE9CF449C64DEDC8B50D48EC";
TRRimecudA613.name = "TR/Rimecud.A.613";

if (filehash == TRRimecudA613.md5)
{

return TRRimecudA613.name;

}

Database::Virus TRDropSmallfup;

TRDropSmallfup.md5 = "c59404a447db1e4320fb6a27f56b036c";
TRDropSmallfup.name = "TR/Drop.Small.fup";

if (filehash == TRDropSmallfup.md5)
{

return TRDropSmallfup.name;

}

Database::Virus TRSpyZbae118784;

TRSpyZbae118784.md5 = "4dc14290fb2cb22e11e3a1d24aa09dc1";
TRSpyZbae118784.name = "TR/Spy.Zb.ae.118784";

if (filehash == TRSpyZbae118784.md5)
{

return TRSpyZbae118784.name;

}

Database::Virus TRSpyZBotahhv;

TRSpyZBotahhv.md5 = "4b3fe3619c4165dc518ffed299c26288";
TRSpyZBotahhv.name = "TR/Spy.ZBot.ahhv";

if (filehash == TRSpyZBotahhv.md5)
{

return TRSpyZBotahhv.name;

}

Database::Virus TRGendal155136;

TRGendal155136.md5 = "1955d85fe94c2441634160e0ed0c9de8";
TRGendal155136.name = "TR/Gendal.155136";

if (filehash == TRGendal155136.md5)
{

return TRGendal155136.name;

}

Database::Virus TRKazy104603;

TRKazy104603.md5 = "D1C5EAE2223366F5447B6C1B5C9953CB";
TRKazy104603.name = "TR/Kazy.10460.3";

if (filehash == TRKazy104603.md5)
{

return TRKazy104603.name;

}

Database::Virus TRDldrCodecPackagey;

TRDldrCodecPackagey.md5 = "13925191223A47584970512FE8352F7A";
TRDldrCodecPackagey.name = "TR/Dldr.CodecPack.agey";

if (filehash == TRDldrCodecPackagey.md5)
{

return TRDldrCodecPackagey.name;

}

Database::Virus TRVBajuh;

TRVBajuh.md5 = "40d69d80ed0f39faa9d9ecb3f9a38683";
TRVBajuh.name = "TR/VB.ajuh";

if (filehash == TRVBajuh.md5)
{

return TRVBajuh.name;

}

Database::Virus TRDropSmallfpl;

TRDropSmallfpl.md5 = "40c06b45abb11d25cdbef2ce91c053bd";
TRDropSmallfpl.name = "TR/Drop.Small.fpl";

if (filehash == TRDropSmallfpl.md5)
{

return TRDropSmallfpl.name;

}

Database::Virus TRAgentb18;

TRAgentb18.md5 = "12ae4642bb27acfcb725d1acefb901c9";
TRAgentb18.name = "TR/Agent.b.18";

if (filehash == TRAgentb18.md5)
{

return TRAgentb18.name;

}

Database::Virus TRDropAgentGH;

TRDropAgentGH.md5 = "066e35aed18f9a36a8bc18cff3a87333";
TRDropAgentGH.name = "TR/Drop.Agent.GH";

if (filehash == TRDropAgentGH.md5)
{

return TRDropAgentGH.name;

}

Database::Virus TRDropPicHutB2;

TRDropPicHutB2.md5 = "b73d8761e9d1c8b56eeae974a50aae69";
TRDropPicHutB2.name = "TR/Drop.PicHut.B.2";

if (filehash == TRDropPicHutB2.md5)
{

return TRDropPicHutB2.name;

}

Database::Virus TRSpySpyEyesxz;

TRSpySpyEyesxz.md5 = "057b530eaf60c6a5371e9ee4078f1a15";
TRSpySpyEyesxz.name = "TR/Spy.SpyEyes.xz";

if (filehash == TRSpySpyEyesxz.md5)
{

return TRSpySpyEyesxz.name;

}

Database::Virus TRGendal162304;

TRGendal162304.md5 = "fec1fcba041ebcfe7569ed7e357e3bb9";
TRGendal162304.name = "TR/Gendal.162304";

if (filehash == TRGendal162304.md5)
{

return TRGendal162304.name;

}

Database::Virus TRClickCyclerakqx;

TRClickCyclerakqx.md5 = "b037c7f84d2aa017a63009cd8312a4ea";
TRClickCyclerakqx.name = "TR/Click.Cycler.akqx";

if (filehash == TRClickCyclerakqx.md5)
{

return TRClickCyclerakqx.name;

}

Database::Virus TRGendal174592;

TRGendal174592.md5 = "cdc8332df0886b7a5ba36569053847f1";
TRGendal174592.name = "TR/Gendal.174592";

if (filehash == TRGendal174592.md5)
{

return TRGendal174592.name;

}

Database::Virus TRSpyZBotER;

TRSpyZBotER.md5 = "6fdee37943255339a981bf85b5486590";
TRSpyZBotER.name = "TR/Spy.ZBot.ER";

if (filehash == TRSpyZBotER.md5)
{

return TRSpyZBotER.name;

}

Database::Virus TRVBajhz;

TRVBajhz.md5 = "d97b49851b8db85ba1113f8c8931f6c8";
TRVBajhz.name = "TR/VB.ajhz";

if (filehash == TRVBajhz.md5)
{

return TRVBajhz.name;

}

Database::Virus TRMonderdihq;

TRMonderdihq.md5 = "4629d1c0f776cad7a6d24fbe5c20a83f";
TRMonderdihq.name = "TR/Monder.dihq";

if (filehash == TRMonderdihq.md5)
{

return TRMonderdihq.name;

}

Database::Virus TRRimecudA131;

TRRimecudA131.md5 = "C9913EB123CDE55F8AB1263585F7D015";
TRRimecudA131.name = "TR/Rimecud.A.131";

if (filehash == TRRimecudA131.md5)
{

return TRRimecudA131.name;

}

Database::Virus TRScarcpmw;

TRScarcpmw.md5 = "de6eaa177cff80f501357be6cd0b704a";
TRScarcpmw.name = "TR/Scar.cpmw";

if (filehash == TRScarcpmw.md5)
{

return TRScarcpmw.name;

}

Database::Virus TRObfuscated29996C;

TRObfuscated29996C.md5 = "31a45141128e82836fd626470E5512f7";
TRObfuscated29996C.name = "TR/Obfuscated.29996.C";

if (filehash == TRObfuscated29996C.md5)
{

return TRObfuscated29996C.name;

}

Database::Virus TRFakeSysdefB;

TRFakeSysdefB.md5 = "77296EC788A6BC37FAC18707D0CBC5A0";
TRFakeSysdefB.name = "TR/FakeSysdef.B";

if (filehash == TRFakeSysdefB.md5)
{

return TRFakeSysdefB.name;

}

Database::Virus TRIrcbruteA166;

TRIrcbruteA166.md5 = "9E1D88B21189A32F5F5816D39F47FE74";
TRIrcbruteA166.name = "TR/Ircbrute.A.166";

if (filehash == TRIrcbruteA166.md5)
{

return TRIrcbruteA166.name;

}

Database::Virus TROnlinegames894;

TROnlinegames894.md5 = "7A7428EF2E4D841E093AD3B6757CD233";
TROnlinegames894.name = "TR/Onlinegames.894";

if (filehash == TROnlinegames894.md5)
{

return TROnlinegames894.name;

}

Database::Virus TRKazy9567;

TRKazy9567.md5 = "308B4119CA69025B627179F63EF844BA";
TRKazy9567.name = "TR/Kazy.9567";

if (filehash == TRKazy9567.md5)
{

return TRKazy9567.name;

}

Database::Virus TRKazy8962C;

TRKazy8962C.md5 = "FD97BDBD99B89AE83F8FC987F37724B5";
TRKazy8962C.name = "TR/Kazy.8962.C";

if (filehash == TRKazy8962C.md5)
{

return TRKazy8962C.name;

}

Database::Virus TRVBKrypt127;

TRVBKrypt127.md5 = "9B02B00807B6EF3BF0483A8C2A99EA27";
TRVBKrypt127.name = "TR/VBKrypt.12.7";

if (filehash == TRVBKrypt127.md5)
{

return TRVBKrypt127.name;

}

Database::Virus TRPSWMagancfdl2;

TRPSWMagancfdl2.md5 = "108f4bdbfc54216a7b5a31bd5966400d";
TRPSWMagancfdl2.name = "TR/PSW.Magan.cfdl.2";

if (filehash == TRPSWMagancfdl2.md5)
{

return TRPSWMagancfdl2.name;

}

Database::Virus TRKazy84804;

TRKazy84804.md5 = "06ac16d5f73d30f5c37b50bbb8a2f249";
TRKazy84804.name = "TR/Kazy.8480.4";

if (filehash == TRKazy84804.md5)
{

return TRKazy84804.name;

}

Database::Virus TROnlineGam105329;

TROnlineGam105329.md5 = "6f948634ab0cbde9ecf77871a3930660";
TROnlineGam105329.name = "TR/OnlineGam.105329";

if (filehash == TROnlineGam105329.md5)
{

return TROnlineGam105329.name;

}

Database::Virus TRAgent7782421;

TRAgent7782421.md5 = "42F4796B65F5DA85F99B937F9AC25C9B";
TRAgent7782421.name = "TR/Agent.77824.21";

if (filehash == TRAgent7782421.md5)
{

return TRAgent7782421.name;

}

Database::Virus TRSpy69632155;

TRSpy69632155.md5 = "418420acc7fe2482e2207c195995d190";
TRSpy69632155.name = "TR/Spy.69632.155";

if (filehash == TRSpy69632155.md5)
{

return TRSpy69632155.name;

}

Database::Virus TRDldrCodecPackaffe;

TRDldrCodecPackaffe.md5 = "7EF21BF08A27D756DB01F08C1806218B";
TRDldrCodecPackaffe.name = "TR/Dldr.CodecPack.affe";

if (filehash == TRDldrCodecPackaffe.md5)
{

return TRDldrCodecPackaffe.name;

}

Database::Virus TRDropSmallfsc;

TRDropSmallfsc.md5 = "2872f81b2769c9d36476eed97c48bd55";
TRDropSmallfsc.name = "TR/Drop.Small.fsc";

if (filehash == TRDropSmallfsc.md5)
{

return TRDropSmallfsc.name;

}

Database::Virus TRPSWOnlineGamesKDNL;

TRPSWOnlineGamesKDNL.md5 = "23396c331547d1119207dd8c42e6bf8f";
TRPSWOnlineGamesKDNL.name = "TR/PSW.OnlineGames.KDNL";

if (filehash == TRPSWOnlineGamesKDNL.md5)
{

return TRPSWOnlineGamesKDNL.name;

}

Database::Virus TRPSWOnlineGamesxafp;

TRPSWOnlineGamesxafp.md5 = "f5ee55354f7d54f1dc931989c314081f";
TRPSWOnlineGamesxafp.name = "TR/PSW.OnlineGames.xafp";

if (filehash == TRPSWOnlineGamesxafp.md5)
{

return TRPSWOnlineGamesxafp.name;

}

Database::Virus TRPSWOnlineGamesamdb;

TRPSWOnlineGamesamdb.md5 = "75801cf247c6ebc6ed75ae787b84f92d";
TRPSWOnlineGamesamdb.name = "TR/PSW.OnlineGames.amdb";

if (filehash == TRPSWOnlineGamesamdb.md5)
{

return TRPSWOnlineGamesamdb.name;

}

Database::Virus TROnlineGam112903;

TROnlineGam112903.md5 = "84236d9cee0b23a063cfd7d37f2025a9";
TROnlineGam112903.name = "TR/OnlineGam.112903";

if (filehash == TROnlineGam112903.md5)
{

return TROnlineGam112903.name;

}

Database::Virus TRKazy6096;

TRKazy6096.md5 = "1875852304c53ad7b03fb8d9fae8b3f2";
TRKazy6096.name = "TR/Kazy.6096";

if (filehash == TRKazy6096.md5)
{

return TRKazy6096.name;

}

Database::Virus TRDldrFakeTeam;

TRDldrFakeTeam.md5 = "5cdbeaa0bc8d66284eb9fc1e5a9c74be";
TRDldrFakeTeam.name = "TR/Dldr.FakeTeam";

if (filehash == TRDldrFakeTeam.md5)
{

return TRDldrFakeTeam.name;

}

Database::Virus TRAgent757761;

TRAgent757761.md5 = "01a8769b1316916d9cc154b7ab817d27";
TRAgent757761.name = "TR/Agent.75776.1";

if (filehash == TRAgent757761.md5)
{

return TRAgent757761.name;

}

Database::Virus TRAgentbq22;

TRAgentbq22.md5 = "27e88f54091ea7ef288a7df8eb54796b";
TRAgentbq22.name = "TR/Agent.bq.22";

if (filehash == TRAgentbq22.md5)
{

return TRAgentbq22.name;

}

Database::Virus TROnlinegames993;

TROnlinegames993.md5 = "29C295321FB289E7968851A1CCC70AD8";
TROnlinegames993.name = "TR/Onlinegames.993";

if (filehash == TROnlinegames993.md5)
{

return TROnlinegames993.name;

}

Database::Virus TRPSWOnlineGamesKDHZ;

TRPSWOnlineGamesKDHZ.md5 = "FE0259DF706942C06FCECC966BD589AB";
TRPSWOnlineGamesKDHZ.name = "TR/PSW.OnlineGames.KDHZ";

if (filehash == TRPSWOnlineGamesKDHZ.md5)
{

return TRPSWOnlineGamesKDHZ.name;

}

Database::Virus TRBuzuseymo;

TRBuzuseymo.md5 = "a605224caa3d089360d9b49ac0de17ed";
TRBuzuseymo.name = "TR/Buzus.eymo";

if (filehash == TRBuzuseymo.md5)
{

return TRBuzuseymo.name;

}

Database::Virus TRZbotHPC;

TRZbotHPC.md5 = "00aee459f1ca55de4404fd0f89027ae0";
TRZbotHPC.name = "TR/Zbot.HPC";

if (filehash == TRZbotHPC.md5)
{

return TRZbotHPC.name;

}

Database::Virus TROnLineGame91129;

TROnLineGame91129.md5 = "5AB2F04F0482BBD28D2F8B32D125052F";
TROnLineGame91129.name = "TR/OnLineGame.91129";

if (filehash == TROnLineGame91129.md5)
{

return TROnLineGame91129.name;

}

Database::Virus TRDropOnGaAU;

TRDropOnGaAU.md5 = "E24A0458C2EF5333B06BE67C7EA47B95";
TRDropOnGaAU.name = "TR/Drop.OnGa.AU";

if (filehash == TRDropOnGaAU.md5)
{

return TRDropOnGaAU.name;

}

Database::Virus TRAgent2124803;

TRAgent2124803.md5 = "12227b120318f70a6c5b2e4477c84bf7";
TRAgent2124803.name = "TR/Agent.212480.3";

if (filehash == TRAgent2124803.md5)
{

return TRAgent2124803.name;

}

Database::Virus TRFraudPackbub74;

TRFraudPackbub74.md5 = "db0a83788f0e1419f1cca8168f30a407";
TRFraudPackbub74.name = "TR/FraudPack.bub.74";

if (filehash == TRFraudPackbub74.md5)
{

return TRFraudPackbub74.name;

}

Database::Virus TRAgentDelfJA;

TRAgentDelfJA.md5 = "f799d22b1500319971162662d6bbbff0";
TRAgentDelfJA.name = "TR/Agent.Delf.JA";

if (filehash == TRAgentDelfJA.md5)
{

return TRAgentDelfJA.name;

}

Database::Virus TRDropAgentabo;

TRDropAgentabo.md5 = "9015f808a4a1b7d56d7b35c33adfaba0";
TRDropAgentabo.name = "TR/Drop.Agent.abo";

if (filehash == TRDropAgentabo.md5)
{

return TRDropAgentabo.name;

}

Database::Virus TRInjectVBBC;

TRInjectVBBC.md5 = "E80063427648F372590BD636124B09EF";
TRInjectVBBC.name = "TR/Inject.VB.BC";

if (filehash == TRInjectVBBC.md5)
{

return TRInjectVBBC.name;

}

Database::Virus TRPalevo14;

TRPalevo14.md5 = "D245F4D776BFB1D78C6D054EE5705721";
TRPalevo14.name = "TR/Palevo.14";

if (filehash == TRPalevo14.md5)
{

return TRPalevo14.name;

}

Database::Virus TRPSWMaganiadbwz;

TRPSWMaganiadbwz.md5 = "c05ba6ef2df45120170c2418cb6b3338";
TRPSWMaganiadbwz.name = "TR/PSW.Magania.dbwz";

if (filehash == TRPSWMaganiadbwz.md5)
{

return TRPSWMaganiadbwz.name;

}

Database::Virus TROnlineGam108084;

TROnlineGam108084.md5 = "88b6b65f09eae79d0925a121e58e3acb";
TROnlineGam108084.name = "TR/OnlineGam.108084";

if (filehash == TROnlineGam108084.md5)
{

return TROnlineGam108084.name;

}

Database::Virus TRDldrAgent3686460;

TRDldrAgent3686460.md5 = "52622abe02aed763086454ec55adb599";
TRDldrAgent3686460.name = "TR/Dldr.Agent.36864.60";

if (filehash == TRDldrAgent3686460.md5)
{

return TRDldrAgent3686460.name;

}

Database::Virus TRVBairv;

TRVBairv.md5 = "440399fb51b03a4136d313cc1eba333d";
TRVBairv.name = "TR/VB.airv";

if (filehash == TRVBairv.md5)
{

return TRVBairv.name;

}

Database::Virus TRVBagln;

TRVBagln.md5 = "04f66de8e847606dd9195893cf9af468";
TRVBagln.name = "TR/VB.agln";

if (filehash == TRVBagln.md5)
{

return TRVBagln.name;

}

Database::Virus TRIrcbruteA115;

TRIrcbruteA115.md5 = "703004C262660EB9A773AD1CBC38E01E";
TRIrcbruteA115.name = "TR/Ircbrute.A.115";

if (filehash == TRIrcbruteA115.md5)
{

return TRIrcbruteA115.name;

}

Database::Virus TRDldrRenosLX15;

TRDldrRenosLX15.md5 = "674556B5F19CA9D7D38057CF143F2518";
TRDldrRenosLX15.name = "TR/Dldr.Renos.LX.15";

if (filehash == TRDldrRenosLX15.md5)
{

return TRDldrRenosLX15.name;

}

Database::Virus TRDropAgentaeo;

TRDropAgentaeo.md5 = "104b2bbf7db4dc032c454c6f262cb1aa";
TRDropAgentaeo.name = "TR/Drop.Agent.aeo";

if (filehash == TRDropAgentaeo.md5)
{

return TRDropAgentaeo.name;

}

Database::Virus TRVBagod;

TRVBagod.md5 = "a7741a3a7b66bee786902e5ea76d80ab";
TRVBagod.name = "TR/VB.agod";

if (filehash == TRVBagod.md5)
{

return TRVBagod.name;

}

Database::Virus TRVBAgentGC;

TRVBAgentGC.md5 = "7085b41ad93da1e0d7577ffd58bbb70f";
TRVBAgentGC.name = "TR/VB.Agent.GC";

if (filehash == TRVBAgentGC.md5)
{

return TRVBAgentGC.name;

}

Database::Virus TRAgent875529;

TRAgent875529.md5 = "410F4DAE19CC08591AE28E76A84A9C0F";
TRAgent875529.name = "TR/Agent.87552.9";

if (filehash == TRAgent875529.md5)
{

return TRAgent875529.name;

}

Database::Virus TRFraudPackkvb77;

TRFraudPackkvb77.md5 = "03c2352f8e4a2a0Ad9bdf1002aa9efad";
TRFraudPackkvb77.name = "TR/FraudPack.kvb.77";

if (filehash == TRFraudPackkvb77.md5)
{

return TRFraudPackkvb77.name;

}

Database::Virus TRVBahuf;

TRVBahuf.md5 = "11a1423cb736d9fd8db4fd8f336a8457";
TRVBahuf.name = "TR/VB.ahuf";

if (filehash == TRVBahuf.md5)
{

return TRVBahuf.name;

}

Database::Virus TRVBagkh;

TRVBagkh.md5 = "02d1516107474caffa1e48a9ea7935bc";
TRVBagkh.name = "TR/VB.agkh";

if (filehash == TRVBagkh.md5)
{

return TRVBagkh.name;

}

Database::Virus TRPSWOnlineGamesOOB1;

TRPSWOnlineGamesOOB1.md5 = "e6d04aa303188528e01f250f32c8322b";
TRPSWOnlineGamesOOB1.name = "TR/PSW.OnlineGames.OOB.1";

if (filehash == TRPSWOnlineGamesOOB1.md5)
{

return TRPSWOnlineGamesOOB1.name;

}

Database::Virus TRDropAgentFO1;

TRDropAgentFO1.md5 = "ab86c5684a73621c69b8083581cdcf04";
TRDropAgentFO1.name = "TR/Drop.Agent.FO.1";

if (filehash == TRDropAgentFO1.md5)
{

return TRDropAgentFO1.name;

}

Database::Virus TRVBagyv;

TRVBagyv.md5 = "0163c1540ec5757613b3bb03794017f3";
TRVBagyv.name = "TR/VB.agyv";

if (filehash == TRVBagyv.md5)
{

return TRVBagyv.name;

}

Database::Virus TRShakato13;

TRShakato13.md5 = "41c02f58da9a8c036150dc20120bff11";
TRShakato13.name = "TR/Shakat.o.13";

if (filehash == TRShakato13.md5)
{

return TRShakato13.name;

}

Database::Virus TRScarbzkj;

TRScarbzkj.md5 = "3d483de902185e61c323312ef6714a35";
TRScarbzkj.name = "TR/Scar.bzkj";

if (filehash == TRScarbzkj.md5)
{

return TRScarbzkj.name;

}

Database::Virus TRKazy70205;

TRKazy70205.md5 = "44483C1EC9B322F20147F67745DCA6AD";
TRKazy70205.name = "TR/Kazy.7020.5";

if (filehash == TRKazy70205.md5)
{

return TRKazy70205.name;

}

Database::Virus TRAgent4812831;

TRAgent4812831.md5 = "464dc356acfdff4a50cea02d73bcb1ed";
TRAgent4812831.name = "TR/Agent.48128.31";

if (filehash == TRAgent4812831.md5)
{

return TRAgent4812831.name;

}

Database::Virus TRAgentakcc;

TRAgentakcc.md5 = "512C1F4D5D137183109003DE074B94F3";
TRAgentakcc.name = "TR/Agent.akcc";

if (filehash == TRAgentakcc.md5)
{

return TRAgentakcc.name;

}

Database::Virus TRAgentAR814;

TRAgentAR814.md5 = "DF29B9866397FD311A5259C5D4BC00DD";
TRAgentAR814.name = "TR/Agent.AR.814";

if (filehash == TRAgentAR814.md5)
{

return TRAgentAR814.name;

}

Database::Virus TRBegSMSA;

TRBegSMSA.md5 = "DF016DD064DBD5B476B53C59902569D2";
TRBegSMSA.name = "TR/BegSMS.A";

if (filehash == TRBegSMSA.md5)
{

return TRBegSMSA.name;

}

Database::Virus TRObfuscatedIX275;

TRObfuscatedIX275.md5 = "ec47f70b9a8175d16fe441d3c5dd0fe0";
TRObfuscatedIX275.name = "TR/Obfuscated.IX.275";

if (filehash == TRObfuscatedIX275.md5)
{

return TRObfuscatedIX275.name;

}

Database::Virus TRMalagentA986;

TRMalagentA986.md5 = "e58ef034c253d8e6ef5593431b85ef61";
TRMalagentA986.name = "TR/Malagent.A.986";

if (filehash == TRMalagentA986.md5)
{

return TRMalagentA986.name;

}

Database::Virus TRSpyAgentabd;

TRSpyAgentabd.md5 = "1695b91b4a13345b9f97527d2d7ca370";
TRSpyAgentabd.name = "TR/Spy.Agent.abd";

if (filehash == TRSpyAgentabd.md5)
{

return TRSpyAgentabd.name;

}

Database::Virus TRAgent81920EA;

TRAgent81920EA.md5 = "5997f7a3c3baec7e8e2cb87b3d984cd6";
TRAgent81920EA.name = "TR/Agent.81920.EA";

if (filehash == TRAgent81920EA.md5)
{

return TRAgent81920EA.name;

}

Database::Virus TRSpyBankerXH10;

TRSpyBankerXH10.md5 = "20F961FBD1E8D56C357465A1C200664E";
TRSpyBankerXH10.name = "TR/Spy.Banker.XH.10";

if (filehash == TRSpyBankerXH10.md5)
{

return TRSpyBankerXH10.name;

}









//End of Microsoft Windows Virus Database


//Linux Virus Database













//End of Linux Virus Database







  else
  {
      return 0;

  }


  //End of Database

   }
