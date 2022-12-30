#! /usr/bin/python3

import atheris
import sys
import io


with atheris.instrument_imports():
    import pyModeS as pms

def fuzz_singleInput(input_bytes):
    fdp = atheris.FuzzedDataProvider(input_bytes)
    data_string = fdp.ConsumeUnicodeNoSurrogates(sys.maxsize)

    msg = data_string
    msg_even = msg
    msg_odd = msg
    t_even = msg
    t_odd = msg
    lat_ref = msg
    lon_ref = msg

    try:
        # pms.df(msg)
        # pms.icao(msg)
        # pms.crc(msg, encode=True)
        # pms.hex2bin(msg)
        # pms.bin2int(msg)
        # pms.hex2int(msg)
        # pms.gray2int(msg)
        # pms.adsb.icao(msg)
        # pms.adsb.typecode(msg)
        pms.adsb.callsign(msg)
        pms.adsb.position(msg_even, msg_odd, t_even, t_odd, lat_ref=None, lon_ref=None)
        pms.adsb.airborne_position(msg_even, msg_odd, t_even, t_odd)
        pms.adsb.surface_position(msg_even, msg_odd, t_even, t_odd, lat_ref, lon_ref)
        pms.adsb.surface_velocity(msg)
        pms.adsb.position_with_ref(msg, lat_ref, lon_ref)
        pms.adsb.airborne_position_with_ref(msg, lat_ref, lon_ref)
        pms.adsb.surface_position_with_ref(msg, lat_ref, lon_ref)
        pms.adsb.altitude(msg)
        pms.adsb.velocity(msg)
        pms.adsb.speed_heading(msg)
        pms.adsb.airborne_velocity(msg)
        pms.common.altcode(msg)
        pms.common.idcode(msg)
        # pms.icao(msg)
        pms.bds.infer(msg)
        pms.bds.bds10.is10(msg)
        # pms.bds.bds17.is17(msg)
        # pms.bds.bds20.is20(msg)
        # pms.bds.bds30.is30(msg)
        # pms.bds.bds40.is40(msg)
        pms.bds.bds44.is44(msg)
        pms.bds.bds50.is50(msg)
        pms.bds.bds60.is60(msg)
        pms.commb.ovc10(msg)
        # pms.commb.cap17(msg)
        # pms.commb.cs20(msg)
        # pms.commb.selalt40mcp(msg)
        # pms.commb.selalt40fms(msg)
        # pms.commb.p40baro(msg)
        # pms.commb.roll50(msg)
        # pms.commb.trk50(msg)
        # pms.commb.gs50(msg)
        # pms.commb.rtrk50(msg)
        # pms.commb.tas50(msg)
        # pms.commb.hdg60(msg)
        # pms.commb.ias60(msg)
        # pms.commb.mach60(msg)
        # pms.commb.vr60baro(msg)
        # pms.commb.vr60ins(msg)
        # pms.commb.wind44(msg)
        # pms.commb.temp44(msg)
        # pms.commb.p44(msg)
        # pms.commb.hum44(msg)
        # pms.commb.turb45(msg)
        # pms.commb.ws45(msg)
        # pms.commb.mb45(msg)
        # pms.commb.ic45(msg)
        # pms.commb.wv45(msg)
        # pms.commb.temp45(msg)
        # pms.commb.p45(msg)
        # pms.commb.rh45(msg)
    except ValueError: # arguably too basic
        pass
    # except IndexError: # arguably logical bugs
    #     pass
    # except TypeError: # arguably logical bugs
    #     pass


def main():
    atheris.Setup(sys.argv, fuzz_singleInput)
    atheris.Fuzz()

if __name__ == "__main__":
    main()