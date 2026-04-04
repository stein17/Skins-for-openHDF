#######################################################################
#
#    Renderer for Enigma2
#    Coded by shamann (c)2011
#
#    This program is free software; you can redistribute it and/or
#    modify it under the terms of the GNU General Public License
#    as published by the Free Software Foundation; either version 2
#    of the License, or (at your option) any later version.
#
#######################################################################

#######################################################################
#
#    Renderer for Enigma2 openHDF
#    Based on GradientFrontend, cleaned and extended with compact
#    frontend output:
#    DVB-S2 11464 H 22000 2/3 8PSK 19.2°E
#
#######################################################################

from Components.Renderer.Renderer import Renderer
from enigma import eLabel
from Components.VariableText import VariableText
from enigma import (
    eServiceCenter,
    iServiceInformation,
    eDVBFrontendParametersSatellite,
    eDVBFrontendParametersCable,
)
from Components.config import config
from gettext import gettext as _
from Tools.Transponder import ConvertToHumanReadable


class GradientFrontend(VariableText, Renderer):

    GUI_WIDGET = eLabel

    def __init__(self):
        Renderer.__init__(self)
        VariableText.__init__(self)
        self.ena = True
        try:
            self.ena = config.plugins.stein17skins
        except Exception:
            pass

    def connect(self, source):
        Renderer.connect(self, source)
        self.changed((self.CHANGED_DEFAULT,))

    def _fmt_orbital(self, sname, human):
        # Always build a compact numeric orbital position like 19.2°E / 0.8°W.
        try:
            if isinstance(sname, dict) and "orbital_position" in sname:
                num_sat = int(sname["orbital_position"])
            else:
                num_sat = None

            if num_sat is None and isinstance(human, dict):
                raw = str(human.get("orb_pos", "") or "").strip()
                if raw.endswith("E") or raw.endswith("W"):
                    suffix = raw[-1]
                    value = float(raw[:-1])
                    if suffix == "W":
                        num_sat = int(round((360.0 - value) * 10))
                    else:
                        num_sat = int(round(value * 10))

            if num_sat is None:
                return ""

            if num_sat > 1800:
                pos = (3600 - num_sat) / 10.0
                return f"{pos:.1f}\u00B0W"

            pos = num_sat / 10.0
            return f"{pos:.1f}\u00B0E"
        except Exception:
            return ""

    def _fmt_pol(self, sname, human):
        try:
            pol = human.get("polarization_abbreviation", "")
            if pol:
                return str(pol) + "  "
        except Exception:
            pass

        try:
            if "polarization" in sname:
                return {
                    eDVBFrontendParametersSatellite.Polarisation_Horizontal: "H  ",
                    eDVBFrontendParametersSatellite.Polarisation_Vertical: "V  ",
                    eDVBFrontendParametersSatellite.Polarisation_CircularLeft: "CL  ",
                    eDVBFrontendParametersSatellite.Polarisation_CircularRight: "CR  ",
                }.get(sname["polarization"], "N/A  ")
        except Exception:
            pass
        return ""

    def _fmt_fec(self, sname, human):
        try:
            fec = human.get("fec_inner", "")
            if fec:
                return str(fec) + "  "
        except Exception:
            pass

        try:
            if "fec_inner" in sname:
                fec = {
                    eDVBFrontendParametersSatellite.FEC_None: _("None"),
                    eDVBFrontendParametersSatellite.FEC_Auto: _("Auto"),
                    eDVBFrontendParametersSatellite.FEC_1_2: "1/2",
                    eDVBFrontendParametersSatellite.FEC_2_3: "2/3",
                    eDVBFrontendParametersSatellite.FEC_3_4: "3/4",
                    eDVBFrontendParametersSatellite.FEC_5_6: "5/6",
                    eDVBFrontendParametersSatellite.FEC_7_8: "7/8",
                    eDVBFrontendParametersSatellite.FEC_3_5: "3/5",
                    eDVBFrontendParametersSatellite.FEC_4_5: "4/5",
                    eDVBFrontendParametersSatellite.FEC_8_9: "8/9",
                    eDVBFrontendParametersSatellite.FEC_9_10: "9/10",
                }.get(sname["fec_inner"], "")
                if not fec:
                    fec = {
                        eDVBFrontendParametersCable.FEC_None: _("None"),
                        eDVBFrontendParametersCable.FEC_Auto: _("Auto"),
                        eDVBFrontendParametersCable.FEC_1_2: "1/2",
                        eDVBFrontendParametersCable.FEC_2_3: "2/3",
                        eDVBFrontendParametersCable.FEC_3_4: "3/4",
                        eDVBFrontendParametersCable.FEC_5_6: "5/6",
                        eDVBFrontendParametersCable.FEC_7_8: "7/8",
                        eDVBFrontendParametersCable.FEC_8_9: "8/9",
                    }.get(sname["fec_inner"], "")
                if fec:
                    return str(fec) + "  "
        except Exception:
            pass
        return ""

    def changed(self, what):
        if not self.instance:
            return

        if what[0] == self.CHANGED_CLEAR:
            self.text = "Transporder info detect failed !"
            return

        try:
            serviceref = self.source.service
        except Exception:
            serviceref = None

        if not serviceref:
            self.text = "Transporder info not detected"
            return

        try:
            info = eServiceCenter.getInstance().info(serviceref)
        except Exception:
            info = None

        if not info:
            self.text = "Transporder info not detected"
            return

        try:
            refstr = serviceref.toString().replace("%3a", ":").replace("%3A", ":")
        except Exception:
            refstr = ""

        try:
            sname = info.getInfoObject(serviceref, iServiceInformation.sTransponderData)
        except Exception:
            sname = None

        if not sname:
            if "://" in refstr:
                try:
                    host = refstr.rsplit("://", 1)[1].split("/")[0]
                    self.text = "Stream " + host
                except Exception:
                    self.text = "Stream"
            else:
                self.text = "Transporder info not detected"
            return

        try:
            human = ConvertToHumanReadable(sname) if sname else {}
        except Exception:
            human = {}

        system = ""
        freq = ""
        pol = ""
        sr = ""
        fec = ""
        mod = ""
        orb = ""

        try:
            system = human.get("system", "") or sname.get("tuner_type", "")
            if system:
                system = str(system).strip() + "  "
        except Exception:
            system = ""

        try:
            if "frequency" in sname:
                tmp = int(sname["frequency"]) / 1000
                if tmp == int(tmp):
                    freq = str(int(tmp)) + "  "
                else:
                    freq = str(tmp) + "  "
        except Exception:
            freq = ""

        pol = self._fmt_pol(sname, human)

        try:
            if "symbol_rate" in sname:
                tmp = int(sname["symbol_rate"]) / 1000
                if tmp == int(tmp):
                    sr = str(int(tmp)) + "  "
                else:
                    sr = str(tmp) + "  "
        except Exception:
            sr = ""

        fec = self._fmt_fec(sname, human)

        try:
            mod = human.get("modulation", "")
            if mod:
                mod = str(mod) + "  "
        except Exception:
            mod = ""

        orb = self._fmt_orbital(sname, human)

        text = (system + freq + pol + sr + fec + mod + orb).strip()
        if text:
            self.text = text
        else:
            if "://" in refstr:
                try:
                    host = refstr.rsplit("://", 1)[1].split("/")[0]
                    self.text = "Stream " + host
                except Exception:
                    self.text = "Stream"
            else:
                self.text = "Transporder info not detected"
