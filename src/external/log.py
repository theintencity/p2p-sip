# Copyright (C) 2010, 2011 Vinay Sajip. All rights reserved.
# Copyright (C) 2011 Kundan Singh. All rights reserved.
# See http://plumberjack.blogspot.com/2010/12/colorizing-logging-output-in-terminals.html

import logging
import os

class ColorizingStreamHandler(logging.StreamHandler):
    # color names to indices
    color_map = {
        'black': 0,
        'red': 1,
        'green': 2,
        'yellow': 3,
        'blue': 4,
        'magenta': 5,
        'cyan': 6,
        'white': 7,
    }

    #levels to (background, foreground, bold/intense)
    if os.name == 'nt':
        level_map = {
            logging.DEBUG: (None, 'blue', True),
            logging.INFO: (None, 'white', False),
            logging.WARNING: (None, 'yellow', True),
            logging.ERROR: (None, 'red', True),
            logging.CRITICAL: ('red', 'white', True),
        }
    else:
        level_map = {
            logging.DEBUG: (None, 'black', False),
            logging.INFO: (None, 'blue', False),
            logging.WARNING: (None, 'red', False),
            logging.ERROR: (None, 'red', False),
            logging.CRITICAL: ('red', 'white', True),
        }
    csi = '\x1b['
    reset = '\x1b[0m'

    @property
    def is_tty(self):
        isatty = getattr(self.stream, 'isatty', None)
        return isatty and isatty()

    def emit(self, record):
        try:
            message = self.format(record)
            stream = self.stream
            if not self.is_tty:
                stream.write(message)
            else:
                self.output_colorized(message)
            stream.write(getattr(self, 'terminator', '\n'))
            self.flush()
        except (KeyboardInterrupt, SystemExit):
            raise
        except:
            self.handleError(record)

    if os.name != 'nt':
        def output_colorized(self, message):
            self.stream.write(message)
    else:
        import ctypes
        import re
        ansi_esc = re.compile(r'\x1b\[((?:\d+)(?:;(?:\d+))*)m')

        nt_color_map = {
            0: 0x00,    # black
            1: 0x04,    # red
            2: 0x02,    # green
            3: 0x06,    # yellow
            4: 0x01,    # blue
            5: 0x05,    # magenta
            6: 0x03,    # cyan
            7: 0x07,    # white
        }

        def output_colorized(self, message):
            parts = self.ansi_esc.split(message)
            write = self.stream.write
            h = None
            fd = getattr(self.stream, 'fileno', None)
            if fd is not None:
                fd = fd()
                if fd in (1, 2): # stdout or stderr
                    try:
                        h = ctypes.windll.kernel32.GetStdHandle(-10 - fd)
                    except: # sometimes it throws "global name ctypes not defined" on Windows.
                        self.stream.write(message)
                        return
            while parts:
                text = parts.pop(0)
                if text:
                    write(text)
                if parts:
                    params = parts.pop(0)
                    if h is not None:
                        params = [int(p) for p in params.split(';')]
                        color = 0
                        for p in params:
                            if 40 <= p <= 47:
                                color |= self.nt_color_map[p - 40] << 4
                            elif 30 <= p <= 37:
                                color |= self.nt_color_map[p - 30]
                            elif p == 1:
                                color |= 0x08 # foreground intensity on
                            elif p == 0: # reset to default color
                                color = 0x07
                            else:
                                pass # error condition ignored
                        ctypes.windll.kernel32.SetConsoleTextAttribute(h, color)

    def colorize(self, message, record):
        if record.levelno in self.level_map:
            bg, fg, bold = self.level_map[record.levelno]
            params = []
            if bg in self.color_map:
                params.append(str(self.color_map[bg] + 40))
            if fg in self.color_map:
                params.append(str(self.color_map[fg] + 30))
            if bold:
                params.append('1')
            if params:
                message = ''.join((self.csi, ';'.join(params),
                                   'm', message, self.reset))
        return message

    def format(self, record):
        message = logging.StreamHandler.format(self, record)
        if self.is_tty:
            # Don't colorize any traceback
            parts = message.split('\n', 1)
            parts[0] = self.colorize(parts[0], record)
            message = '\n'.join(parts)
        return message


#import socket
#
#class MessageFlowHandler(logging.Handler):
#    def __init__(self, target=('255.255.255.255', 8060)):
#        logging.StreamHandler.__init__(self)
#        self.sock = socket.socket(type=socket.SOCK_DGRAM)
#        self.target = target
#        
#    def emit(self, record):
#        try:
#            message = self.format(record)
#            self.sock.sendto(message, self.target)
#        except (KeyboardInterrupt, SystemExit):
#            raise
#        except:
#            self.handleError(record)

repeats = {}

def repeated_warning(context, logger, condition, message, count=500):
    '''
    Allows displaying repeated warning messages only onces and then periodically every count times
    instead of every time. This is useful for displaying media path related warning messages without overloading
    the log.
    
    @param  context: the context under which this warning happened. The repeat count is stored for each context
    for each message.
    @param logger: the logger object to use as logger.warning
    @param condition: the condition (boolean) for display or count the warning, and false to clear the warning.
    @param message: the error message should be exactly the same each time in repeated invocations.
    @param count: how many times to ignore for repeated display.
    @return: boolean indicating whether the message was displayed or not. If there are more details that change
    in each call to this within an error message, then the return value should be used to determine whether
    more details needs to be printed or not.
    '''
    global repeats
    if context not in repeats: messages = repeats[context] = {}
    else: messages = repeats[context]
    result = False
    if condition:
        if message not in messages:
            logger.warning(message)
            messages[message], result = 0, True
        elif messages[message] >= count:
            logger.warning(message + ' -- repeated %r times', messages[message])
            messages[message], result = 0, True
        else:
            messages[message] += 1
    elif message in messages:
        if messages[message] > 0:
            logger.warning(message + ' -- repeated %r times', messages[message])
            result = True
        del messages[message]
    return result

def main():
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    root.addHandler(ColorizingStreamHandler())
    logging.debug('DEBUG')
    logging.info('INFO')
    logging.warning('WARNING')
    logging.error('ERROR')
    logging.critical('CRITICAL')

if __name__ == '__main__':
    main()
