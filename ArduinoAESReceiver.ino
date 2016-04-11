/*
   Open Energy Monitor

   Base Receiver Arduino code - for upload onto Raspberry Pi emonBase module
   https://openenergymonitor.org/emon/emonbase/raspberrypi

   Allows the reception of RFM packets from sensors using new payload format and AES128 encryption

   Passes data to PI as Base64 encoded strings with checksums to prevent bad packets being
   received by the PI

   Feb 22 2016 
   Stuart Pittaway


  Compiled with Arduino 1.6.7


   Useful links
   https://wiki.openenergymonitor.org/index.php/RFM69Pi_V3
   http://forum.arduino.cc/index.php?topic=124879.0
*/

//Comment out to not have a flashing LED

//NANODE RF = Digital 5	Green LED, Digital 6 Red LED
#define LED_PIN 5
//Arduino uses standard HW Serial port
#define HWSERIAL Serial

//Baud rate is 38400 for Rasp Pi
#define BAUD_RATE 38400

//RFM module chip select pin D10 (SPI bus)
#define RF12_CS_PIN 10

const uint8_t debug = 0;

#include <AESLib.h>

#define RF69_COMPAT 0                                                 // Set to 1 if using RFM69CW or 0 is using RFM12B
#include <JeeLib.h>                                                   // https://github.com/jcw/jeelib - Tested with JeeLib 3/11/14
#include <util/crc16.h>

#define RF_freq RF12_433MHZ                                           // Frequency of RF12B module can be RF12_433MHZ, RF12_868MHZ or RF12_915MHZ. You should use the one matching the module you have.
int nodeID = 30;                                                      //  RFM12B node ID - should be unique on network
const int networkGroup = 210;                                         //network group - needs to be same as emonBase and emonGLCD

static void activityLed (byte on) {
#ifdef LED_PIN
  pinMode(LED_PIN, OUTPUT);
  digitalWrite(LED_PIN, on);
#endif
}

/*
   Globals
*/
//Hold BASE64 encoded character buffer - maximum is double the RFM buffer (2 * 66 bytes)
char outBuffer[RF12_MAXDATA * 2];

//Input serial buffers
static char inputString[RF12_MAXDATA * 2];
char* inputStringPtr;
byte charCounter = 0;


inline char i2h(uint8_t i)
{
  char k = i & 0x0F;
  if (k <= 9)
    return '0' + k;
  else
    return ('A' + k) - 10;
}

static void dumpHex(uint8_t number)
{
  if (debug == 1)
  {
    HWSERIAL.print(i2h(number >> 4));
    HWSERIAL.print(i2h(number));
  }
}

static void dumpBytes (char *ptr, byte len) {
  if (debug == 1)
  {
    for (uint8_t i = 0; i < len; i++) {
      dumpHex( ptr[i] );
    }
    HWSERIAL.print("\n");
  }
}


void LEDPattern(uint8_t ledPin, int loop, int delay1, int delay2) {
  pinMode(ledPin, OUTPUT);
  for (int i = 0; i < loop; i++) {
    digitalWrite(ledPin, HIGH);
    delay(delay1);
    digitalWrite(ledPin, LOW);
    delay(delay1);
    digitalWrite(ledPin, HIGH);
    delay(delay1);
    digitalWrite(ledPin, LOW);
    delay(delay2);
  }
}

/*
   SETUP ROUTINE
*/
void setup() {

  LEDPattern(LED_PIN, 5, 175, 250);

  activityLed(0);
  HWSERIAL.begin(BAUD_RATE);
  HWSERIAL.println(F("#Version:" __DATE__ "@" __TIME__));

#if !defined(RF69_COMPAT)
  rf12_set_cs  ( RF12_CS_PIN ) ;
#endif

  rf12_initialize(nodeID, RF_freq, networkGroup);                       // Initialize RFM12B

  HWSERIAL.print(F("#Node:"));
  HWSERIAL.println(nodeID);
  HWSERIAL.print(F("#Group:"));
  HWSERIAL.println(networkGroup);
  HWSERIAL.print(F("#Freq:"));
  HWSERIAL.println(RF_freq);

  HWSERIAL.println(F("#Ready"));

  ResetStringBuffer();

  rf12_sleep(RF12_WAKEUP);

  activityLed(1);
}

//Left in RAM to ensure its fast
const unsigned char b64_alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

inline void a3_to_a4(unsigned char * a4, unsigned char * a3) {
  a4[0] = (a3[0] & 0xfc) >> 2;
  a4[1] = ((a3[0] & 0x03) << 4) + ((a3[1] & 0xf0) >> 4);
  a4[2] = ((a3[1] & 0x0f) << 2) + ((a3[2] & 0xc0) >> 6);
  a4[3] = (a3[2] & 0x3f);
}

inline void a4_to_a3(unsigned char * a3, unsigned char * a4) {
  a3[0] = (a4[0] << 2) + ((a4[1] & 0x30) >> 4);
  a3[1] = ((a4[1] & 0xf) << 4) + ((a4[2] & 0x3c) >> 2);
  a3[2] = ((a4[2] & 0x3) << 6) + a4[3];
}

int base64_encode(char *output, char *input, int inputLen) {
  /*
    Taken from https://github.com/adamvr/arduino-base64
    Modifed to put alphabet table back into RAM to improve speed of conversion
  */
  int i = 0, j = 0;
  int encLen = 0;
  unsigned char a3[3];
  unsigned char a4[4];

  while (inputLen--) {
    a3[i++] = *(input++);
    if (i == 3) {
      a3_to_a4(a4, a3);

      for (i = 0; i < 4; i++) {
        output[encLen++] = b64_alphabet[a4[i]];
      }

      i = 0;
    }
  }

  if (i) {
    for (j = i; j < 3; j++) {
      a3[j] = '\0';
    }

    a3_to_a4(a4, a3);

    for (j = 0; j < i + 1; j++) {
      output[encLen++] = b64_alphabet[a4[j]];
    }

    while ((i++ < 3)) {
      output[encLen++] = '=';
    }
  }
  output[encLen] = '\0';
  return encLen;
}


inline unsigned char b64_lookup(char c) {
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 71;
  if (c >= '0' && c <= '9') return c + 4;
  if (c == '+') return 62;
  if (c == '/') return 63;
  return -1;
}

int base64_decode(char * output, char * input, int inputLen) {
  int i = 0, j = 0;
  int decLen = 0;
  unsigned char a3[3];
  unsigned char a4[4];

  while (inputLen--) {
    if (*input == '=') {
      break;
    }

    a4[i++] = *(input++);
    if (i == 4) {
      for (i = 0; i < 4; i++) {
        a4[i] = b64_lookup(a4[i]);
      }

      a4_to_a3(a3, a4);

      for (i = 0; i < 3; i++) {
        output[decLen++] = a3[i];
      }
      i = 0;
    }
  }

  if (i) {
    for (j = i; j < 4; j++) {
      a4[j] = '\0';
    }

    for (j = 0; j < 4; j++) {
      a4[j] = b64_lookup(a4[j]);
    }

    a4_to_a3(a3, a4);

    for (j = 0; j < i - 1; j++) {
      output[decLen++] = a3[j];
    }
  }
  output[decLen] = '\0';
  return decLen;
}



void ResetStringBuffer() {
  inputString[0] = 0;
  inputStringPtr = &inputString[0];
  charCounter = 0;
}

//CRC-16 (Modbus) calculation
static word calcCrc (const void* ptr, uint8_t len) {
  word crc = ~0;
  for (uint8_t i = 0; i < len; ++i)
    crc = _crc16_update(crc, ((const uint8_t*) ptr)[i]);
  return crc;
}

void SendPacketOverRFM() {
  //Convert our base64 encoded string into bytes
  int packetLength = base64_decode(outBuffer, inputString, charCounter);

  //We should check the CRC16 of the buffer now to ensure we received the serial data okay.
  word calculatedCRC = calcCrc(&outBuffer, packetLength);

  if (calculatedCRC != 0) {
    HWSERIAL.println(F("BadInputCRC"));
    return;
  }

  //Now we send the bytes (blindly!) over the RFM transmitter
  //If we are expecting an ACK reply to our transmission, then try up to 4 times, otherwise its a single shot
  bool everythingGood = false;
  byte retryCount = 4;

  //Clear buffer if something is sitting in it
  while (!rf12_canSend()) {
    rf12_recvDone();
  }

  while (everythingGood == false && retryCount > 0) {

    //Send our packet directly to the base and ask for an ACK
    rf12_sendStart(outBuffer[1], &outBuffer[3], packetLength - 2);
    rf12_sendWait(1);

    if ((outBuffer[1] & RF12_HDR_ACK) == RF12_HDR_ACK) {
      //We should now wait for an ACK to turn up from sensor, max 350ms (dont make this too long or you may miss inbound packets)
      MilliTimer t1;
      while (!t1.poll(350)) {
        // got an empty packet intended for us
        if (rf12_recvDone()) {
          if ((rf12_crc == 0) && rf12_hdr == (RF12_HDR_DST | RF12_HDR_CTL | nodeID)) {
            everythingGood = true;
          }
        }
      }
    } else {
      everythingGood = true;
    }

    retryCount--;
  }

  //Report out the success (or not) of the ACK, along with two bytes from the message (message type and destination node)
  HWSERIAL.print("#");
  if (!everythingGood) {
    HWSERIAL.print(F("No"));
  }
  HWSERIAL.print(F("Ack:0x"));
  dumpHex(outBuffer[3]);
  dumpHex(outBuffer[4]);
  HWSERIAL.print("\n");
}

void ProcessIncomingCommandFromBase() {
  //We have received a string from the base station, process it here

  //Quickly clear the buffer
  memset(outBuffer, 0, sizeof(outBuffer));

  if (inputString[0] == '!') {
    //Its a command for the ATMEL not to be sent over air
    HWSERIAL.println("#NotImplemented");
  } else {
    SendPacketOverRFM();
  }

  //Reset string buffer here as we have now finished with it
  ResetStringBuffer();
}

static unsigned long badPacketCounter = 0;
static unsigned long badCRCPacketCounter = 0;
static unsigned long packetCounter = 0;

static void ProcessRFMPacket() {

  //dumpBytes((char *)&rf12_buf, rf12_len);

  //      HWSERIAL.print("#rf12_crc:");HWSERIAL.println(rf12_crc);
  //HWSERIAL.print("#rf12_hdr:"); HWSERIAL.println(rf12_hdr,HEX);

  //XXX AAAAA
  //‭011 11110‬ = 0x7E
  //‭XX1 XXXXX‬=RF12_ACK_REPLY - The A bit (ACK) indicates whether this packet wants to get an ACK back.
  //‭X1X XXXXX‬=RF12_HDR_DST - The D bit (DST) indicates whether the node ID specifies the destination node or the source node. For packets sent to a specific node, DST = 1
  //1XX XXXXX=RF12_HDR_CTL - The C bit (CTL) is used to send ACKs, and in turn must be combined with the A bit set to zero.
  //We only respond to packets directly sent to the base station (with RF12_HDR_DST bit flag set)

  if ( rf12_crc != 0) {
    badCRCPacketCounter++;
    HWSERIAL.println(F("#Error:CRC"));
    return;
  }

  if ( (rf12_hdr & RF12_HDR_MASK ) != nodeID) {
    badPacketCounter++;
    HWSERIAL.println(F("#Error:NotMyAddress"));
    return;
  }

  if ( (rf12_hdr & RF12_HDR_DST) != RF12_HDR_DST) {
    badPacketCounter++;
    HWSERIAL.println(F("#Error:Broadcast"));
    return;
  }

  packetCounter++;

#if RF69_COMPAT
  //Output RSSI every 5 packets (bit random but saves flooding the serial port with these statements)
  if (packetCounter % 5 == 0) {
    byte rssi = (RF69::rssi >> 1);
    HWSERIAL.print("#RSSI:");
    HWSERIAL.print(rf12_data[0]); HWSERIAL.print(',');
    HWSERIAL.println(- rssi);
  }
#endif

  if (packetCounter % 10 == 0) {
    HWSERIAL.print("#STATS:");
    HWSERIAL.print(badCRCPacketCounter); HWSERIAL.print(',');
    HWSERIAL.print(badPacketCounter); HWSERIAL.print(',');
    HWSERIAL.println(packetCounter);
  }

  //Flash
  activityLed(1);

  //Quickly clear the buffer (also sets end of line string for base 64 encode function)
  memset(outBuffer, 0, sizeof(outBuffer));

  //Encode the bytes into base64 and put into outBuffer
  //rf12_len is a define from the JeeLib library
  base64_encode(outBuffer, ( char*)&rf12_buf, rf12_len + 3 + 2);

  //Print out the buffer (its null terminated already by the memset above)
  HWSERIAL.println(outBuffer);
  //HWSERIAL.print('\n');

  if (RF12_WANTS_ACK) {
    //If we need to reply with an ACK then send it back to the node that asked for it - stored in byte zero of the packet data
    //We are still limited to the JEELIB RFM code in that it only allows 30 nodes to talk on the same network group
    rf12_sendStart(RF12_ACK_REPLY | RF12_HDR_DST | (rf12_data[0] & RF12_HDR_MASK), 0, 0);
    rf12_sendWait(1);
  }

  //Flash
  activityLed(0);
}
/*
   The main loop
   We sit and wait for a packet of data to arrive from the RFM chip, assuming it is valid (ie. received without error)
   we then convert that whole packet into a sequence of BASE64 encoded characters and transmit over serial
   to the Raspberry PI

   Each line is sent as a sequence of characters, then a CR to indicate end of packet/line

   We send the entire RFM packet as it already contains a CRC checksum that the Raspberry PI can use to check the
   serial connection was okay as there isn't any hardware CTS/RTS on the Arduino

   Ideally we wouldn't convert to Base64 first as this can double the amount of data (and effectively halves the baud rate) but it is really useful for debugging!
   Its also easy to find Base64 decoders in most populate languages like Python and C#
*/
void loop() {
  while (Serial.available()) {
    // get the new byte:
    char inChar = (char)Serial.read();

    //inputStringPtr
    if (charCounter < sizeof inputString) {

      if (inChar == '\n') {
        *inputStringPtr = 0;
        inputStringPtr++;
        ProcessIncomingCommandFromBase();
      } else {
        // add it to the inputString:
        *inputStringPtr = inChar;
        inputStringPtr++;
        charCounter++;
        // if the incoming character is a newline, set a flag
        // so the main loop can do something about it:
      }
    } else {
      //Prevent buffer/memory overflow errors crashing Arduino, so reset string
      ResetStringBuffer();
    }
  }

  while (rf12_recvDone()) {
    ProcessRFMPacket();
  }
}

