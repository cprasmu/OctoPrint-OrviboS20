# coding=utf-8
from __future__ import absolute_import

import octoprint.plugin
from octoprint.server import user_permission
from contextlib import contextmanager
import socket
import json
import logging
import os
import re
import threading
import time
import struct
import select
import random
import binascii
import sys

py3 = sys.version_info[0] == 3

BROADCAST = '255.255.255.255'
PORT = 10000

MAGIC = b'\x68\x64'
SPACES_6 = b'\x20\x20\x20\x20\x20\x20'
ZEROS_4 = b'\x00\x00\x00\x00'

ON = b'\x01'
OFF = b'\x00'

# CMD CODES
DISCOVER = b'\x71\x61'
DISCOVER_RESP = DISCOVER

SUBSCRIBE = b'\x63\x6c'
SUBSCRIBE_RESP = SUBSCRIBE

CONTROL = b'\x64\x63'
CONTROL_RESP = CONTROL

SOCKET_EVENT = b'\x73\x66' # something happend with socket

LEARN_IR = b'\x6c\x73'
LEARN_IR_RESP = LEARN_IR

BLAST_IR = b'\x69\x63'

BLAST_RF433 = CONTROL
LEARN_RF433 = CONTROL

class OrviboException(Exception):
    """ Module level exception class.
    """
    def __init__(self, msg):
        super(OrviboException, self).__init__(msg)

def _reverse_bytes(mac):
    """ Helper method to reverse bytes order.
    mac -- bytes to reverse
    """
    ba = bytearray(mac)
    ba.reverse()
    return bytes(ba)

def _random_byte():
    """ Generates random single byte.
    """
    return bytes([int(256 * random.random())])

def _random_n_bytes(n):
    res = b''
    for n in range(n):
        res += _random_byte()
    return res

def _packet_id():
    return _random_n_bytes(2)

_placeholders = ['MAGIC', 'SPACES_6', 'ZEROS_4', 'CONTROL', 'CONTROL_RESP', 'SUBSCRIBE', 'LEARN_IR', 'BLAST_RF433', 'BLAST_IR', 'DISCOVER', 'DISCOVER_RESP' ]
def _debug_data(data):
    data = binascii.hexlify(bytearray(data))
    for s in _placeholders:
        p = binascii.hexlify(bytearray( globals()[s]))
        data = data.replace(p, b" + " + s.encode() + b" + ")
    return data[3:]

def _parse_discover_response(response):
    """ Extracts MAC address and Type of the device from response.
    response -- dicover response, format:
                MAGIC + LENGTH + DISCOVER_RESP + b'\x00' + MAC + SPACES_6 + REV_MAC + ... TYPE
    """
    header_len = len(MAGIC + DISCOVER_RESP) + 2 + 1  # 2 length bytes, and 0x00
    mac_len = 6
    spaces_len = len(SPACES_6)

    mac_start = header_len
    mac_end = mac_start + mac_len
    mac = response[mac_start:mac_end]

    type = None
    if b'SOC' in response:
        type = Orvibo.TYPE_SOCKET


    return (type, mac)

def _create_orvibo_socket(ip=''):
    """ Creates socket to talk with Orvibo devices.
    Arguments:
    ip - ip address of the Orvibo device or empty string in case of broadcasting discover packet.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for opt in [socket.SO_BROADCAST, socket.SO_REUSEADDR, socket.SO_BROADCAST]:
        sock.setsockopt(socket.SOL_SOCKET, opt, 1)
    if ip:
        sock.connect((ip, PORT))
    else:
        sock.bind((ip, PORT))
    return sock

@contextmanager
def _orvibo_socket(external_socket = None):
    sock = _create_orvibo_socket() if external_socket is None else external_socket

    yield sock

    if external_socket is None:
        sock.close()
    else:
        pass

class Packet:
    """ Represents response sender/recepient address and binary data.
    """

    Request = 'request'
    Response = 'response'

    def __init__(self, ip = BROADCAST, data = None, type = Request):
        self.ip = ip
        self.data = data
        self.type = type

    def __repr__(self):
        return 'Packet {} {}: {}'.format('to' if self.type == self.Request else 'from', self.ip, _debug_data(self.data))

    @property
    def cmd(self):
        """ 2 bytes command of the orvibo packet
        """
        if self.data is None:
            return b''
        return self.data[4:6]

    @property
    def length(self):
        """ 2 bytes command of the orvibo packet
        """
        if self.data is None:
            return b''
        return self.data[2:4]


    def send(self, sock, timeout = 10):
        """ Sends binary packet via socket.
        Arguments:
        sock -- socket to send through
        packet -- byte string to send
        timeout -- number of seconds to wait for sending operation
        """
        if self.data is None:
            # Nothing to send
            return

        for i in range(timeout):
            r, w, x = select.select([], [sock], [sock], 1)
            if sock in w:
                sock.sendto(bytearray(self.data), (self.ip, PORT))
            elif sock in x:
                raise OrviboException("Failed while sending packet.")
            else:
                # nothing to send
                break

    @staticmethod
    def recv(sock, expectResponseType = None, timeout = 10):
        """ Receive first packet from socket of given type
        Arguments:
        sock -- socket to listen to
        expectResponseType -- 2 bytes packet command type to filter result data
        timeout -- number of seconds to wait for response
        """
        response = None
        for i in range(10):
            r, w, x = select.select([sock], [], [sock], 1)
            if sock in r:
                data, addr = sock.recvfrom(1024)

                if expectResponseType is not None and data[4:6] != expectResponseType:
                    continue

                response = Packet(addr[0], data, Packet.Response)
                break
            elif sock in x:
                raise OrviboException('Getting response failed')
            else:
                # Nothing to read
                break

        return response

    @staticmethod
    def recv_all(sock, expectResponseType = None, timeout = 10):
       res = None
       while True:
           resp = Packet.recv(sock, expectResponseType, timeout)
           if resp is None:
                break
           res = resp
       return res

    def compile(self, *args):
        """ Assemblies packet to send to orvibo device.
        *args -- number of bytes strings that will be concatenated, and prefixed with MAGIC heaer and packet length.
        """

        length = len(MAGIC) + 2 # len itself
        packet = b''
        for a in args:
            length += len(a)
            packet += a

        msg_len_2 = struct.pack('>h', length)
        self.data = MAGIC + msg_len_2 + packet
        return self

class Orvibo(object):
    """ Represents Orvibo device, such as wifi socket (TYPE_SOCKET)
    """

    TYPE_SOCKET = 'socket'

    def __init__(self, ip, mac = None, type = 'Unknown'):
        self.ip = ip
        self.type = type
        self.__last_subscr_time = time.time() - 1 # Orvibo doesn't like subscriptions frequently that 1 in 0.1sec
        self.__logger = logging.getLogger('{}@{}'.format(self.__class__.__name__, ip))
        self.__socket = None
        self.mac = mac

        # TODO: make this tricky code clear
        if py3 and isinstance(mac, str):
            self.mac = binascii.unhexlify(mac)
        else:
            try:
                self.mac = binascii.unhexlify(mac)
            except:
                pass

        if mac is None:
            self.__logger.debug('MAC address is not provided. Discovering..')
            d = Orvibo.discover(self.ip)
            self.mac = d.mac
            self.type = d.type

    def __del__(self):
        self.close()

    def close(self):
        if self.__socket is not None:
            try:
                self.__socket.close()
            except socket.error:
                # socket seems not alive
                pass
            self.__socket = None

    @property
    def keep_connection(self):
        """ Keeps connection to the Orvibo device.
        """
        return self.__socket is not None

    @keep_connection.setter
    def keep_connection(self, value):
        """ Keeps connection to the Orvibo device.
        """
        # Close connection if alive
        self.close()

        if value:
            self.__socket = _create_orvibo_socket(self.ip)
            if self.__subscribe(self.__socket) is None:
                raise OrviboException('Connection subscription error.')
        else:
            self.close()

    def __repr__(self):
        mac = binascii.hexlify(bytearray(self.mac))
        return "Orvibo[type={}, ip={}, mac={}]".format(self.type, 'Unknown' if self.ip == BROADCAST else self.ip, mac.decode('utf-8') if py3 else mac)

    @staticmethod
    def discover(ip = None):
        """ Discover all/exact devices in the local network
        Arguments:
        ip -- ip address of the discovered device
        returns -- map {ip : (ip, mac, type)} of all discovered devices if ip argument is None
                   Orvibo object that represents device at address ip.
        raises -- OrviboException if requested ip not found
        """
        devices = {}
        with _orvibo_socket() as s:
            logger = logging.getLogger(Orvibo.__class__.__name__)
            logger.debug('Discovering Orvibo devices')
            discover_packet = Packet(BROADCAST)
            discover_packet.compile(DISCOVER)
            discover_packet.send(s)

            for indx in range(512): # supposer there are less then 512 devices in the network
                p = discover_packet.recv(s)
                if p is None:
                    # No more packets in the socket
                    break

                orvibo_type, orvibo_mac = _parse_discover_response(p.data)
                logger.debug('Discovered values: type={}, mac={}'.format(orvibo_type, orvibo_mac));

                if not orvibo_mac:
                    # Filter ghosts devices
                    continue

                devices[p.ip] = (p.ip, orvibo_mac, orvibo_type)

        if ip is None:
            return devices

        if ip not in devices.keys():
            raise OrviboException('Device ip={} not found in {}.'.format(ip, devices.keys()))

        return Orvibo(*devices[ip])

    def subscribe(self):
        """ Subscribe to device.
        returns -- last response byte, which represents device state
        """
        with _orvibo_socket(self.__socket) as s:
            return self.__subscribe(s)

    def __subscribe(self, s):
        """ Required action after connection to device before sending any requests
        Arguments:
        s -- socket to use for subscribing
        returns -- last response byte, which represents device state
        """

        if time.time() - self.__last_subscr_time < 0.1:
            time.sleep(0.1)

        subscr_packet = Packet(self.ip)
        subscr_packet.compile(SUBSCRIBE, self.mac, SPACES_6, _reverse_bytes(self.mac), SPACES_6)
        subscr_packet.send(s)
        response = subscr_packet.recv_all(s, SUBSCRIBE_RESP)

        self.__last_subscr_time = time.time()
        return response.data[-1] if response is not None else None

    def __control_s20(self, switchOn):
        """ Switch S20 wifi socket on/off
        Arguments:
        switchOn -- True to switch on socket, False to switch off
        returns -- True if switch success, otherwise False
        """

        with _orvibo_socket(self.__socket) as s:
            curr_state = self.__subscribe(s)

            if self.type != Orvibo.TYPE_SOCKET:
                self.__logger.warn('Attempt to control device with type {} as socket.'.format(self.type))
                return False

            if curr_state is None:
                self.__logger.warn('Subscription failed while controlling wifi socket')
                return False

            state = ON if switchOn else OFF
            if curr_state == state:
                self.__logger.warn('No need to switch {0} device which is already switched {0}'.format('on' if switchOn else 'off'))
                return False

            self.__logger.debug('Socket is switching {}'.format('on' if switchOn else 'off'))
            on_off_packet = Packet(self.ip)
            on_off_packet.compile(CONTROL, self.mac, SPACES_6, ZEROS_4, state)
            on_off_packet.send(s)
            if on_off_packet.recv(s, CONTROL_RESP) is None:
                self.__logger.warn('Socket switching {} failed.'.format('on' if switchOn else 'off'))
                return False

            self.__logger.info('Socket is switched {} successfuly.'.format('on' if switchOn else 'off'))
            return True

    @property
    def on(self):
        """ State property for TYPE_SOCKET
        Arguments:
        returns -- State of device (True for on/False for off).
        """

        onValue = 1 if py3 else ON
        return self.subscribe() == onValue

    @on.setter
    def on(self, state):
        """ Change device state for TYPE_SOCKET
        Arguments:
        state -- True (on) or False (off).
        returns -- nothing
        """
        self.__control_s20(state)

class orvibos20Plugin(octoprint.plugin.SettingsPlugin,
                            octoprint.plugin.AssetPlugin,
                            octoprint.plugin.TemplatePlugin,
							octoprint.plugin.SimpleApiPlugin,
							octoprint.plugin.StartupPlugin):

	def __init__(self):
		self._logger = logging.getLogger("octoprint.plugins.orvibos20")
		self._orvibos20_logger = logging.getLogger("octoprint.plugins.orvibos20.debug")

	##~~ StartupPlugin mixin

	def on_startup(self, host, port):
		# setup customized logger
		from octoprint.logging.handlers import CleaningTimedRotatingFileHandler
		orvibos20_logging_handler = CleaningTimedRotatingFileHandler(self._settings.get_plugin_logfile_path(postfix="debug"), when="D", backupCount=3)
		orvibos20_logging_handler.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s: %(message)s"))
		orvibos20_logging_handler.setLevel(logging.DEBUG)

		self._orvibos20_logger.addHandler(orvibos20_logging_handler)
		self._orvibos20_logger.setLevel(logging.DEBUG if self._settings.get_boolean(["debug_logging"]) else logging.INFO)
		self._orvibos20_logger.propagate = False

	def on_after_startup(self):
		self._logger.info("orvibos20 loaded!")

	##~~ SettingsPlugin mixin

	def get_settings_defaults(self):
		return dict(
			debug_logging = False,
			arrSmartplugs = [{'ip':'','label':'','icon':'icon-bolt','displayWarning':True,'warnPrinting':False,'gcodeEnabled':False,'gcodeOnDelay':0,'gcodeOffDelay':0,'autoConnect':True,'autoConnectDelay':10.0,'autoDisconnect':True,'autoDisconnectDelay':0,'sysCmdOn':False,'sysRunCmdOn':'','sysCmdOnDelay':0,'sysCmdOff':False,'sysRunCmdOff':'','sysCmdOffDelay':0,'currentState':'unknown','btnColor':'#808080','useCountdownRules':False,'countdownOnDelay':0,'countdownOffDelay':0}],
			pollingInterval = 15,
			pollingEnabled = False
		)

	def on_settings_save(self, data):
		old_debug_logging = self._settings.get_boolean(["debug_logging"])

		octoprint.plugin.SettingsPlugin.on_settings_save(self, data)

		new_debug_logging = self._settings.get_boolean(["debug_logging"])
		if old_debug_logging != new_debug_logging:
			if new_debug_logging:
				self._orvibos20_logger.setLevel(logging.DEBUG)
			else:
				self._orvibos20_logger.setLevel(logging.INFO)

	def get_settings_version(self):
		return 5

	def on_settings_migrate(self, target, current=None):
		if current is None or current < self.get_settings_version():
			# Reset plug settings to defaults.
			self._logger.debug("Resetting arrSmartplugs for orvibos20 settings.")
			self._settings.set(['arrSmartplugs'], self.get_settings_defaults()["arrSmartplugs"])

	##~~ AssetPlugin mixin

	def get_assets(self):
		return dict(
			js=["js/orvibos20.js"],
			css=["css/orvibos20.css"]
		)

	##~~ TemplatePlugin mixin

	def get_template_configs(self):
		return [
			dict(type="navbar", custom_bindings=True),
			dict(type="settings", custom_bindings=True)
		]

	##~~ SimpleApiPlugin mixin

	def turn_on(self, plugip):
		self._orvibos20_logger.debug("Turning on %s." % plugip)

		d = Orvibo.discover(plugip)

		plug = self.plug_search(self._settings.get(["arrSmartplugs"]),"ip",plugip)
		self._orvibos20_logger.debug(plug)
		#if plug["useCountdownRules"]:
			#self.sendCommand('{"count_down":{"delete_all_rules":null}}',plug["ip"])
			#chk = self.sendCommand('{"count_down":{"add_rule":{"enable":1,"delay":%s,"act":1,"name":"turn on"}}}' % plug["countdownOnDelay"],plug["ip"])["count_down"]["add_rule"]["err_code"]
		#else:
			#chk = self.sendCommand('{"system":{"set_relay_state":{"state":1}}}',plugip)["system"]["set_relay_state"]["err_code"]
		chk = d.on(True)

		if chk == 0:
			self.check_status(plugip)
			if plug["autoConnect"]:
				c = threading.Timer(int(plug["autoConnectDelay"]),self._printer.connect)
				c.start()
			if plug["sysCmdOn"]:
				t = threading.Timer(int(plug["sysCmdOnDelay"]),os.system,args=[plug["sysRunCmdOn"]])
				t.start()

	def turn_off(self, plugip):
		self._orvibos20_logger.debug("Turning off %s." % plugip)
		d = Orvibo.discover(plugip)
    	d.on = False

		plug = self.plug_search(self._settings.get(["arrSmartplugs"]),"ip",plugip)
		self._orvibos20_logger.debug(plug)
		#if plug["useCountdownRules"]:
		#	self.sendCommand('{"count_down":{"delete_all_rules":null}}',plug["ip"])
		#	chk = self.sendCommand('{"count_down":{"add_rule":{"enable":1,"delay":%s,"act":0,"name":"turn off"}}}' % plug["countdownOffDelay"],plug["ip"])["count_down"]["add_rule"]["err_code"]

		if plug["sysCmdOff"]:
			t = threading.Timer(int(plug["sysCmdOffDelay"]),os.system,args=[plug["sysRunCmdOff"]])
			t.start()
		if plug["autoDisconnect"]:
			self._printer.disconnect()
			time.sleep(int(plug["autoDisconnectDelay"]))

		if not plug["useCountdownRules"]:
			chk = d.on(False)

		if chk == 0:
			self.check_status(plugip)

	def check_status(self, plugip):
		self._orvibos20_logger.debug("Checking status of %s." % plugip)
		d = Orvibo.discover(plugip)

		if plugip != "":
			chk = d.on
			if chk == 1:
				self._plugin_manager.send_plugin_message(self._identifier, dict(currentState="on",ip=plugip))
			elif chk == 0:
				self._plugin_manager.send_plugin_message(self._identifier, dict(currentState="off",ip=plugip))
			else:
				self._orvibos20_logger.debug(response)
				self._plugin_manager.send_plugin_message(self._identifier, dict(currentState="unknown",ip=plugip))

	def get_api_commands(self):
		return dict(turnOn=["ip"],turnOff=["ip"],checkStatus=["ip"])

	def on_api_command(self, command, data):
		if not user_permission.can():
			from flask import make_response
			return make_response("Insufficient rights", 403)

		if command == 'turnOn':
			self.turn_on("{ip}".format(**data))
		elif command == 'turnOff':
			self.turn_off("{ip}".format(**data))
		elif command == 'checkStatus':
			self.check_status("{ip}".format(**data))

	##~~ Utilities

	def plug_search(self, list, key, value):
		for item in list:
			if item[key] == value:
				return item


	##~~ Gcode processing hook

	def gcode_turn_off(self, plug):
		if plug["warnPrinting"] and self._printer.is_printing():
			self._logger.info("Not powering off %s because printer is printing." % plug["label"])
		else:
			self.turn_off(plug["ip"])

	def processGCODE(self, comm_instance, phase, cmd, cmd_type, gcode, *args, **kwargs):
		if gcode:
			if cmd.startswith("M80"):
				plugip = re.sub(r'^M80\s?', '', cmd)
				self._orvibos20_logger.debug("Received M80 command, attempting power on of %s." % plugip)
				plug = self.plug_search(self._settings.get(["arrSmartplugs"]),"ip",plugip)
				self._orvibos20_logger.debug(plug)
				if plug["gcodeEnabled"]:
					t = threading.Timer(int(plug["gcodeOnDelay"]),self.turn_on,args=[plugip])
					t.start()
				return
			elif cmd.startswith("M81"):
				plugip = re.sub(r'^M81\s?', '', cmd)
				self._orvibos20_logger.debug("Received M81 command, attempting power off of %s." % plugip)
				plug = self.plug_search(self._settings.get(["arrSmartplugs"]),"ip",plugip)
				self._orvibos20_logger.debug(plug)
				if plug["gcodeEnabled"]:
					t = threading.Timer(int(plug["gcodeOffDelay"]),self.gcode_turn_off,[plug])
					t.start()
				return
			else:
				return

		elif cmd.startswith("@ORVIBOON"):
			plugip = re.sub(r'^@ORVIBOON\s?', '', cmd)
			self._orvibos20_logger.debug("Received @ORVIBOON command, attempting power on of %s." % plugip)
			plug = self.plug_search(self._settings.get(["arrSmartplugs"]),"ip",plugip)
			self._orvibos20_logger.debug(plug)
			if plug["gcodeEnabled"]:
				t = threading.Timer(int(plug["gcodeOnDelay"]),self.turn_on,args=[plugip])
				t.start()
			return None
		elif cmd.startswith("@ORVIBOOFF"):
			plugip = re.sub(r'^@ORVIBOOFF\s?', '', cmd)
			self._orvibos20_logger.debug("Received ORVIBOOFF command, attempting power off of %s." % plugip)
			plug = self.plug_search(self._settings.get(["arrSmartplugs"]),"ip",plugip)
			self._orvibos20_logger.debug(plug)
			if plug["gcodeEnabled"]:
				t = threading.Timer(int(plug["gcodeOffDelay"]),self.gcode_turn_off,[plug])
				t.start()
			return None

	##~~ Softwareupdate hook

	def get_update_information(self):
		# Define the configuration for your plugin to use with the Software Update
		# Plugin here. See https://github.com/foosel/OctoPrint/wiki/Plugin:-Software-Update
		# for details.
		return dict(
			orvibos20=dict(
				displayName="Orvibo S20 Socket",
				displayVersion=self._plugin_version,

				# version check: github repository
				type="github_release",
				user="cprasmu",
				repo="OctoPrint-OrviboS20",
				current=self._plugin_version,

				# update method: pip
				pip="https://github.com/cprasmu/OctoPrint-OrviboS20/archive/{target_version}.zip"
			)
		)


# If you want your plugin to be registered within OctoPrint under a different name than what you defined in setup.py
# ("OctoPrint-PluginSkeleton"), you may define that here. Same goes for the other metadata derived from setup.py that
# can be overwritten via __plugin_xyz__ control properties. See the documentation for that.
__plugin_name__ = "OctoPrint-OrviboS20"

def __plugin_load__():
	global __plugin_implementation__
	__plugin_implementation__ = orvibos20Plugin()

	global __plugin_hooks__
	__plugin_hooks__ = {
		"octoprint.comm.protocol.gcode.queuing": __plugin_implementation__.processGCODE,
		"octoprint.plugin.softwareupdate.check_config": __plugin_implementation__.get_update_information
	}

