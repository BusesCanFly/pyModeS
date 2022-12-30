#! /usr/bin/python3

import atheris
import sys
import io


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

    try:
        pms.df(msg)                 # Downlink Format
        pms.icao(msg)               # Infer the ICAO address from the message
        pms.crc(msg, encode=False)  # Perform CRC or generate parity bit

        pms.hex2bin(msg)      # Convert hexadecimal string to binary string
        pms.bin2int(msg)      # Convert binary string to integer
        pms.hex2int(msg)      # Convert hexadecimal string to integer
        pms.gray2int(msg)     # Convert grey code to integer

        pms.adsb.icao(msg)
        pms.adsb.typecode(msg)

        # Typecode 1-4
        pms.adsb.callsign(msg)

        # Typecode 5-8 (surface), 9-18 (airborne, barometric height), and 20-22 (airborne, GNSS height)
        pms.adsb.position(msg_even, msg_odd, t_even, t_odd, lat_ref=None, lon_ref=None)
        pms.adsb.airborne_position(msg_even, msg_odd, t_even, t_odd)
        pms.adsb.surface_position(msg_even, msg_odd, t_even, t_odd, lat_ref, lon_ref)
        pms.adsb.surface_velocity(msg)

        pms.adsb.position_with_ref(msg, lat_ref, lon_ref)
        pms.adsb.airborne_position_with_ref(msg, lat_ref, lon_ref)
        pms.adsb.surface_position_with_ref(msg, lat_ref, lon_ref)

        pms.adsb.altitude(msg)

        # Typecode: 19
        pms.adsb.velocity(msg)          # Handles both surface & airborne messages
        pms.adsb.speed_heading(msg)     # Handles both surface & airborne messages
        pms.adsb.airborne_velocity(msg)

        pms.common.altcode(msg)   # Downlink format must be 4 or 20

        pms.common.idcode(msg)   # Downlink format must be 5 or 21

        pms.icao(msg)           # Infer the ICAO address from the message
        pms.bds.infer(msg)      # Infer the Modes-S BDS register

        # Check each BDS explicitly
        pms.bds.bds10.is10(msg)
        pms.bds.bds17.is17(msg)
        pms.bds.bds20.is20(msg)
        pms.bds.bds30.is30(msg)
        pms.bds.bds40.is40(msg)
        pms.bds.bds44.is44(msg)
        pms.bds.bds50.is50(msg)
        pms.bds.bds60.is60(msg)

        pms.commb.ovc10(msg)      # Overlay capability, BDS 1,0
        pms.commb.cap17(msg)      # GICB capability, BDS 1,7
        pms.commb.cs20(msg)       # Callsign, BDS 2,0

        # BDS 4,0
        pms.commb.selalt40mcp(msg)   # MCP/FCU selected altitude (ft)
        pms.commb.selalt40fms(msg)   # FMS selected altitude (ft)
        pms.commb.p40baro(msg)    # Barometric pressure (mb)

        # BDS 5,0
        pms.commb.roll50(msg)     # Roll angle (deg)
        pms.commb.trk50(msg)      # True track angle (deg)
        pms.commb.gs50(msg)       # Ground speed (kt)
        pms.commb.rtrk50(msg)     # Track angle rate (deg/sec)
        pms.commb.tas50(msg)      # True airspeed (kt)

        # BDS 6,0
        pms.commb.hdg60(msg)      # Magnetic heading (deg)
        pms.commb.ias60(msg)      # Indicated airspeed (kt)
        pms.commb.mach60(msg)     # Mach number (-)
        pms.commb.vr60baro(msg)   # Barometric altitude rate (ft/min)
        pms.commb.vr60ins(msg)    # Inertial vertical speed (ft/min)

        # BDS 4,4
        pms.commb.wind44(msg)     # Wind speed (kt) and direction (true) (deg)
        pms.commb.temp44(msg)     # Static air temperature (C)
        pms.commb.p44(msg)        # Average static pressure (hPa)
        pms.commb.hum44(msg)      # Humidity (%)

        # BDS 4,5
        pms.commb.turb45(msg)     # Turbulence level (0-3)
        pms.commb.ws45(msg)       # Wind shear level (0-3)
        pms.commb.mb45(msg)       # Microburst level (0-3)
        pms.commb.ic45(msg)       # Icing level (0-3)
        pms.commb.wv45(msg)       # Wake vortex level (0-3)
        pms.commb.temp45(msg)     # Static air temperature (C)
        pms.commb.p45(msg)        # Average static pressure (hPa)
        pms.commb.rh45(msg)       # Radio height (ft)
    # except ValueError:
    #     pass
    # except IndexError:
    #     pass
    # except TypeError:
    #     pass


def main():
    atheris.Setup(sys.argv, fuzz_singleInput)
    atheris.Fuzz()

if __name__ == "__main__":
    main()