#! /usr/bin/python3

import atheris
import sys
import io

from random import randint

with atheris.instrument_imports():
    import pyModeS as pms

def fuzz_singleInput(input_bytes):
    fdp = atheris.FuzzedDataProvider(input_bytes)
    data_string = fdp.ConsumeUnicodeNoSurrogates(sys.maxsize)
    data_int = fdp.ConsumeInt(sys.maxsize)

    msg = data_string
    msg_even = msg
    msg_odd = msg
    t_even = msg
    t_odd = msg
    lat_ref = msg
    lon_ref = msg

    rand = randint(0, 61)

    try:
        if rand == 0:
            pms.df(msg)                 # Downlink Format
        elif rand == 1:
            pms.icao(msg)               # Infer the ICAO address from the message
        elif rand == 2:
            pms.crc(msg, encode=False)  # Perform CRC or generate parity bit
        elif rand == 3:
            pms.hex2bin(msg)      # Convert hexadecimal string to binary string
        elif rand == 4:
            pms.bin2int(msg)      # Convert binary string to integer
        elif rand == 5:
            pms.hex2int(msg)      # Convert hexadecimal string to integer
        elif rand == 6:
            pms.gray2int(msg)     # Convert grey code to integer
        elif rand == 7:
            pms.adsb.icao(msg)
        elif rand == 8:
            pms.adsb.typecode(msg)
        elif rand == 9:
            pms.adsb.callsign(msg)
        elif rand == 10:
            pms.adsb.position(msg_even, msg_odd, t_even, t_odd, lat_ref=None, lon_ref=None)
        elif rand == 11:
            pms.adsb.airborne_position(msg_even, msg_odd, t_even, t_odd)
        elif rand == 12:
            pms.adsb.surface_position(msg_even, msg_odd, t_even, t_odd, lat_ref, lon_ref)
        elif rand == 13:
            pms.adsb.surface_velocity(msg)
        elif rand == 14:
            pms.adsb.position_with_ref(msg, lat_ref, lon_ref)
        elif rand == 15:
            pms.adsb.airborne_position_with_ref(msg, lat_ref, lon_ref)
        elif rand == 16:
            pms.adsb.surface_position_with_ref(msg, lat_ref, lon_ref)
        elif rand == 17:
            pms.adsb.altitude(msg)
        elif rand == 18:
            pms.adsb.velocity(msg)          # Handles both surface & airborne messages
        elif rand == 19:
            pms.adsb.speed_heading(msg)     # Handles both surface & airborne messages
        elif rand == 20:
            pms.adsb.airborne_velocity(msg)
        elif rand == 21:
            pms.common.altcode(msg)   # Downlink format must be 4 or 20
        elif rand == 22:
            pms.common.idcode(msg)   # Downlink format must be 5 or 21
        elif rand == 23:
            pms.icao(msg)           # Infer the ICAO address from the message
        elif rand == 24:
            pms.bds.infer(msg)      # Infer the Modes-S BDS register
        elif rand == 25:
            pms.bds.bds10.is10(msg)
        elif rand == 26:
            pms.bds.bds17.is17(msg)
        elif rand == 27:
            pms.bds.bds20.is20(msg)
        elif rand == 28:
            pms.bds.bds30.is30(msg)
        elif rand == 29:
            pms.bds.bds40.is40(msg)
        elif rand == 30:
            pms.bds.bds44.is44(msg)
        elif rand == 31:
            pms.bds.bds50.is50(msg)
        elif rand == 32:
            pms.bds.bds60.is60(msg)
        elif rand == 33:
            pms.commb.ovc10(msg)      # Overlay capability, BDS 1,0
        elif rand == 34:
            pms.commb.cap17(msg)      # GICB capability, BDS 1,7
        elif rand == 35:
            pms.commb.cs20(msg)       # Callsign, BDS 2,0
        elif rand == 36:
            pms.commb.selalt40mcp(msg)   # MCP/FCU selected altitude (ft)
        elif rand == 37:
            pms.commb.selalt40fms(msg)   # FMS selected altitude (ft)
        elif rand == 38:
            pms.commb.p40baro(msg)    # Barometric pressure (mb)
        elif rand == 39:
            pms.commb.roll50(msg)     # Roll angle (deg)
        elif rand == 40:
            pms.commb.trk50(msg)      # True track angle (deg)
        elif rand == 41:
            pms.commb.gs50(msg)       # Ground speed (kt)
        elif rand == 42:
            pms.commb.rtrk50(msg)     # Track angle rate (deg/sec)
        elif rand == 43:
            pms.commb.tas50(msg)      # True airspeed (kt)
        elif rand == 44:
            pms.commb.hdg60(msg)      # Magnetic heading (deg)
        elif rand == 45:
            pms.commb.ias60(msg)      # Indicated airspeed (kt)
        elif rand == 46:
            pms.commb.mach60(msg)     # Mach number (-)
        elif rand == 47:
            pms.commb.vr60baro(msg)   # Barometric altitude rate (ft/min)
        elif rand == 48:
            pms.commb.vr60ins(msg)    # Inertial vertical speed (ft/min)
        elif rand == 49:
            pms.commb.wind44(msg)     # Wind speed (kt) and direction (true) (deg)
        elif rand == 50:
            pms.commb.temp44(msg)     # Static air temperature (C)
        elif rand == 51:
            pms.commb.p44(msg)        # Average static pressure (hPa)
        elif rand == 52:
            pms.commb.hum44(msg)      # Humidity (%)
        elif rand == 53:
            pms.commb.turb45(msg)     # Turbulence level (0-3)
        elif rand == 54:
            pms.commb.ws45(msg)       # Wind shear level (0-3)
        elif rand == 55:
            pms.commb.mb45(msg)       # Microburst level (0-3)
        elif rand == 56:
            pms.commb.ic45(msg)       # Icing level (0-3)
        elif rand == 57:
            pms.commb.wv45(msg)       # Wake vortex level (0-3)
        elif rand == 58:
            pms.commb.temp45(msg)     # Static air temperature (C)
        elif rand == 59:
            pms.commb.p45(msg)        # Average static pressure (hPa)
        elif rand == 60:
            pms.commb.rh45(msg)       # Radio height (ft)%
    except ValueError:
        pass
    # except IndexError:
    #     pass
    # except TypeError:
    #     pass


def main():
    atheris.Setup(sys.argv, fuzz_singleInput)
    atheris.Fuzz()

if __name__ == "__main__":
    main()