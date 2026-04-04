from Components.Converter.Converter import Converter
from enigma import iServiceInformation, iPlayableService, iPlayableServicePtr, eServiceCenter
from Components.Element import cached
from ServiceReference import resolveAlternate
from Tools.Transponder import ConvertToHumanReadable
from gettext import gettext as _


class GradientTransponderInfo(Converter):
	def __init__(self, type):
		Converter.__init__(self, type)
		self.type = type.split(";") if type else []

	@cached
	def getText(self):
		service = self.source.service
		if isinstance(service, iPlayableServicePtr):
			info = service and service.info()
			ref = None
		else:
			info = service and self.source.info
			ref = service

		if not info:
			return ""

		if ref:
			nref = resolveAlternate(ref)
			if nref:
				ref = nref
				info = eServiceCenter.getInstance().info(ref)
			transponderraw = info.getInfoObject(ref, iServiceInformation.sTransponderData)
			ref = ref.toString().replace("%3a", ":")
		else:
			transponderraw = info.getInfoObject(iServiceInformation.sTransponderData)
			ref = info.getInfoString(iServiceInformation.sServiceref)

		if transponderraw:
			transponderdata = ConvertToHumanReadable(transponderraw)
			try:
				onid, tsid = [int(x, 16) for x in ref.split(":")[4:6]]
			except Exception:
				onid, tsid = 0, 0

			if not transponderdata.get("system"):
				transponderdata["system"] = transponderraw.get("tuner_type", "None")

			try:
				if "DVB-T" in transponderdata["system"]:
					return "%s %s-%s %s %d MHz %s" % (
						transponderdata["system"],
						tsid,
						onid,
						transponderdata["channel"],
						transponderdata["frequency"] / 1000000 + 0.5,
						transponderdata["bandwidth"]
					)
				elif "DVB-C" in transponderdata["system"]:
					return "%s %s-%s %d MHz %d %s %s" % (
						transponderdata["system"],
						tsid,
						onid,
						transponderdata["frequency"] / 1000 + 0.5,
						transponderdata["symbol_rate"] / 1000 + 0.5,
						transponderdata["fec_inner"],
						transponderdata["modulation"]
					)
				elif "ATSC" in transponderdata["system"]:
					return "%s %s-%s %d MHz %s" % (
						transponderdata["system"],
						tsid,
						onid,
						transponderdata["frequency"] / 1000 + 0.5,
						transponderdata["modulation"]
					)
				return "%s %s-%s %d %s %d %s %s %s" % (
					transponderdata["system"],
					tsid,
					onid,
					transponderdata["frequency"] / 1000 + 0.5,
					transponderdata["polarization_abbreviation"],
					transponderdata["symbol_rate"] / 1000 + 0.5,
					transponderdata["fec_inner"],
					transponderdata["modulation"],
					transponderdata["orbital_position"] if "detailed_satpos" in self.type else transponderdata["orb_pos"]
				)
			except Exception:
				return ""

		if ref and "://" in ref:
			return _("Stream") + " " + ref.rsplit("://", 1)[1].split("/")[0]

		return ""

	text = property(getText)

	@cached
	def getBoolean(self):
		s = self.getText()
		s = s and s.strip().split() and s.strip().split()[0].lower()
		t = self.type and [x.lower() for x in self.type if x]
		return bool(s and t and s in t)

	boolean = property(getBoolean)

	def changed(self, what):
		if what[0] != self.CHANGED_SPECIFIC or what[1] in (iPlayableService.evStart,):
			Converter.changed(self, what)