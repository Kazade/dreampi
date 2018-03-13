import miniupnpc

class PortForwarding:
    """
        This class is used to forward the ports of all supported Dreamcast games
        automatically, if supported by the network.

        This needs python-miniupnpc installed (or your distro's equivalent).
    """

    # List of ports and the game they're for
    PORTS = [
        (1028,  'UDP', 'Planet Ring'),
        (1285,  'UDP', 'Planet Ring'),
        (3512,  'TCP', 'The Next Tetris: Online Edition'),
        (3512,  'UDP', 'The Next Tetris: Online Edition'),
        (6001,  'UDP', 'Ooga Booga'),
        (6500,  'UDP', 'PBA Tour Bowling 2001 / Starlancer'),
        (7648,  'UDP', 'Planet Ring'),
        (7980,  'UDP', 'Alien Front Online'),
        (9789,  'UDP', 'ChuChu Rocket!'),
        (13139, 'UDP', 'PBA Tour Bowling 2001'),
        (13713, 'UDP', 'World Series Baseball 2K2'),
        (17219, 'TCP', 'Worms World Party'),
        (37171, 'UDP', 'World Series Baseball 2K2'),
        (47624, 'TCP', 'PBA Tour Bowling 2001 / Starlancer'),
        (range(2300, 2401), 'TCP', 'PBA Tour Bowling 2001 / Starlancer'),
        (range(2300, 2401), 'UDP', 'PBA Tour Bowling 2001 / Starlancer')
    ]

    def __init__(self, dc_ip, logger):
        self._dreamcast_ip = dc_ip
        self._logger = logger
        self._upnp = miniupnpc.UPnP()

    def forward_all(self):
        """
            This method deletes all forwards and then re-creates them if possible.
        """

        if self.delete_all():
            for portinfo in self.PORTS:
                port, proto, game = portinfo

                if isinstance(port, list):
                    self._logger.info("Trying to create UPnP port mapping for {} ({}-{}/{})".format(game, port[0], port[-1], proto))

                    for p in port:
                        try:
                            self._upnp.addportmapping(p, proto, self._dreamcast_ip, p, "DreamPi: {}".format(game), '')
                        except Exception as e:
                            self._logger.warn("Could not create UPnP port mapping for {} ({}/{}): {}".format(game, p, proto, e))
                else:
                    self._logger.info("Trying to create UPnP port mapping for {} ({}/{})".format(game, port, proto))

                    try:
                        self._upnp.addportmapping(port, proto, self._dreamcast_ip, port, "DreamPi: {}".format(game), '')
                    except Exception as e:
                        self._logger.warn("Could not create UPnP port mapping for {} ({}/{}): {}".format(game, port, proto, e))

    def delete_all(self):
        """
            This method deletes all forwards, if possible. If the process returns an
            error, we keep trucking.
        """

        try:
            self._upnp.detect()
            self._upnp.selectigd()
        except Exception as e:
            self._logger.info("Could not find a UPnP internet gateway device on your network. Not automatically forwarding ports.")
            return False

        for portinfo in self.PORTS:
            port, proto, game = portinfo

            if isinstance(port, list):
                self._logger.info("Trying to delete UPnP port mapping for {} ({}-{}/{})".format(game, port[0], port[-1], proto))

                for p in port:
                    try:
                        self._upnp.deleteportmapping(p, proto)
                    except Exception as e:
                        self._logger.debug("Could not delete UPnP port mapping for {} ({}/{}): {}".format(game, p, proto, e))
            else:
                self._logger.info("Trying to delete UPnP port mapping for {} ({}/{})".format(game, port, proto))

                try:
                    self._upnp.deleteportmapping(port, proto)
                except Exception as e:
                    self._logger.debug("Could not delete UPnP port mapping for {} ({}/{}): {}".format(game, port, proto, e))

        return True
