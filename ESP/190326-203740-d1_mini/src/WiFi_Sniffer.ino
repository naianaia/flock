/*
  Copyright 2017 Andreas Spiess

  Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"),
  to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense,
  and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE
  FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

  This software is based on the work of Ray Burnette: https://www.hackster.io/rayburne/esp8266-mini-sniff-f6b93a
*/

#include <ESP8266WiFi.h>
#include <ESP8266HTTPClient.h>
#include <ArduinoJson.h>
// #include <credentials.h>
#include <set>
#include <string>
#include "./functions.h"
#include "./mqtt.h"

#define disable 0
#define enable  1
#define SENDTIME 30000
#define MAXDEVICES 60
#define JBUFFER 15+ (MAXDEVICES * 40)
#define PURGETIME 600000
#define MINRSSI -80
#define GROUP_NAME "archive"

// uint8_t channel = 1;
unsigned int channel = 1;
int clients_known_count_old, aps_known_count_old;
unsigned long sendEntry, deleteEntry;
char jsonString[JBUFFER];

//WiFiClient newClient;
const char* host = "192.168.86.131";

String device[MAXDEVICES];
int nbrDevices = 0;
int usedChannels[15];

String chipIdStr = String(ESP.getChipId());

#ifndef CREDENTIALS
#define mySSID "Sourceress"
#define myPASSWORD "stillalive"
#endif

StaticJsonBuffer<JBUFFER>  jsonBuffer;
HTTPClient http;

void setup() {
  Serial.begin(115200);
  Serial.printf("\n\nSDK version:%s\n\r", system_get_sdk_version());
  Serial.println(F("Human detector by Andreas Spiess. ESP8266 mini-sniff by Ray Burnette http://www.hackster.io/rayburne/projects"));
  Serial.println(F("Based on the work of Ray Burnette http://www.hackster.io/rayburne/projects"));

  wifi_set_opmode(STATION_MODE);            // Promiscuous works only with station mode
  wifi_set_channel(channel);
  wifi_promiscuous_enable(disable);
  wifi_set_promiscuous_rx_cb(promisc_cb);   // Set up promiscuous callback
  wifi_promiscuous_enable(enable);
}




void loop() {
  channel = 1;
  boolean sendMQTT = false;
  wifi_set_channel(channel);
  while (true) {
    nothing_new++;                          // Array is not finite, check bounds and adjust if required
    if (nothing_new > 200) {                // monitor channel for 200 ms
      nothing_new = 0;
      channel++;
      if (channel == 15) break;             // Only scan channels 1 to 14
      wifi_set_channel(channel);
    }
    delay(1);  // critical processing timeslice for NONOS SDK! No delay(0) yield()

    if (clients_known_count > clients_known_count_old) {
      clients_known_count_old = clients_known_count;
      sendMQTT = true;
    }
    if (aps_known_count > aps_known_count_old) {
      aps_known_count_old = aps_known_count;
      sendMQTT = true;
    }
    if (millis() - sendEntry > SENDTIME) {
      sendEntry = millis();
      sendMQTT = true;
    }
  }
  purgeDevice();
  if (sendMQTT) {
    showDevices();
    sendDevices();
  }
}


void connectToWiFi() {
  delay(10);
  // We start by connecting to a WiFi network
  Serial.println();
  Serial.print("Connecting to ");
  Serial.println(mySSID);

  WiFi.mode(WIFI_STA);
  WiFi.begin(mySSID, myPASSWORD);

  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }

  Serial.println("");
  Serial.println("WiFi connected");
  Serial.println("IP address: ");
  Serial.println(WiFi.localIP());
}

void purgeDevice() {
  for (int u = 0; u < clients_known_count; u++) {
    if ((millis() - clients_known[u].lastDiscoveredTime) > PURGETIME) {
      Serial.print("purge Client" );
      Serial.println(u);
      for (int i = u; i < clients_known_count; i++) memcpy(&clients_known[i], &clients_known[i + 1], sizeof(clients_known[i]));
      clients_known_count--;
      break;
    }
  }
  for (int u = 0; u < aps_known_count; u++) {
    if ((millis() - aps_known[u].lastDiscoveredTime) > PURGETIME) {
      Serial.print("purge Bacon" );
      Serial.println(u);
      for (int i = u; i < aps_known_count; i++) memcpy(&aps_known[i], &aps_known[i + 1], sizeof(aps_known[i]));
      aps_known_count--;
      break;
    }
  }
}


void showDevices() {
  Serial.println("");
  Serial.println("");
  Serial.println("-------------------Device DB-------------------");
  Serial.printf("%4d Devices + Clients.\n",aps_known_count + clients_known_count); // show count

  // show Beacons
  for (int u = 0; u < aps_known_count; u++) {
    Serial.printf( "%4d ",u); // Show beacon number
    Serial.print("B ");
    Serial.print(formatMac1(aps_known[u].bssid));
    Serial.print(" RSSI ");
    Serial.print(aps_known[u].rssi);
    Serial.print(" channel ");
    Serial.println(aps_known[u].channel);
  }

  // show Clients
  for (int u = 0; u < clients_known_count; u++) {
    Serial.printf("%4d ",u); // Show client number
    Serial.print("C ");
    Serial.print(formatMac1(clients_known[u].station));
    Serial.print(" RSSI ");
    Serial.print(clients_known[u].rssi);
    Serial.print(" channel ");
    Serial.println(clients_known[u].channel);
  }
}

unsigned long long getUnixTime() {
#ifdef ESP32
  time_t now;
  struct tm timeinfo;
  if (!getLocalTime(&timeinfo)) {
    Serial.println("[ ERROR ]\tFailed to obtain time via NTP. Retrying.");
    getUnixTime();
  }
  else
  {
    Serial.println("[ INFO ]\tSuccessfully obtained time via NTP.");
  }
  time(&now);
  unsigned long long uTime = (uintmax_t)now;
  return uTime * 1000UL;
#else
  return 123456;
#endif
}

void sendDevices() {
    String deviceMac;

    // Setup MQTT
    wifi_promiscuous_enable(disable);
    connectToWiFi();

    const int port = 8004;
    String request = "test";


    if (!client.connect("192.168.86.131", port)) {
        Serial.println("connection failed");
    }

        // We now create a URI for the request
    String url = "/echo";


  // This will send the request to the server
    //client.print(fullRequest);
               

    jsonBuffer.clear();
    JsonObject& root = jsonBuffer.createObject();

    root["d"] = chipIdStr;
    root["f"] = GROUP_NAME;
    root["t"] = getUnixTime();
    JsonObject& data = root.createNestedObject("s");
    JsonObject& wifi_network = data.createNestedObject("wifi");

    for (int u = 0; u < aps_known_count; u++) {
        deviceMac = formatMac1(aps_known[u].bssid);
        if (aps_known[u].rssi > MINRSSI) {
            wifi_network[deviceMac] = aps_known[u].rssi;
        }
    }
    for (int u = 0; u < clients_known_count; u++) {
        deviceMac = formatMac1(clients_known[u].station);
        if (clients_known[u].rssi > MINRSSI) {
            wifi_network[deviceMac] = clients_known[u].rssi;
        }
    }


//{"MAC":["d8:6c:63:cc:72:ae","c8:d3:ff:c6:2c:ce","88:3d:24:6e:8b:2d","e4:f0:42:ef:84:52","96:9f:3e:c2:09:d9","d8:6c:63:cc:71:8a","9c:b6:d0:01:92:ef","e4:f0:42:ef:84:4c","bc:dd:c2:25:a2:06","9c:b6:d0:f0:b2:4f","bc:dd:c2:25:f2:7e","88:3d:24:6e:8b:27","24:a2:e1:43:c7:e1","54:33:cb:9f:72:e1","54:60:09:c2:16:7e","f4:f5:d8:a4:90:08","38:8b:59:4a:7d:eb","a4:77:33:f5:9f:70","00:17:88:4c:85:06","90:b6:86:01:73:b5","9c:f3:87:b6:c3:96","5c:aa:fd:5e:c2:7e","00:55:da:52:bd:e8","94:9f:3e:c2:09:d9","20:91:48:bf:49:81","c8:d3:ff:c6:2c:cd","68:54:fd:34:5e:ee","f0:18:98:07:95:5a"]}
/**
    JsonArray& mac = root.createNestedArray("MAC");
    // add Beacons
    for (int u = 0; u < aps_known_count; u++) {
        deviceMac = formatMac1(aps_known[u].bssid);
        if (aps_known[u].rssi > MINRSSI) {
        mac.add(deviceMac);
        //    rssi.add(aps_known[u].rssi);
        }
    }

    // Add Clients
    for (int u = 0; u < clients_known_count; u++) {
        deviceMac = formatMac1(clients_known[u].station);
        if (clients_known[u].rssi > MINRSSI) {
        mac.add(deviceMac);
        //    rssi.add(clients_known[u].rssi);
        }
    }**/
    Serial.println("find3 string begin");
    Serial.println(jsonString);
    Serial.println("find3 string end");
    //Serial.printf("number of devices: %02d\n", mac.size());
    root.prettyPrintTo(Serial);
    root.printTo(jsonString);


    

    http.begin("http://192.168.86.131:"+port);
    http.addHeader("Content-Type", "application/json");
    http.POST(jsonString);
    http.writeToStream(&Serial);
    http.end();

/**
    String fullRequest = String("POST ") + url + " HTTP/1.1\r\n" +
            "Host: http://" + host + ":" + port + "\r\n" +
            "Content-Type: text/plain\r\n\r\n\r\n" +
            jsonString +
            "\r\n\r\n";**/

//"Content-Length: " + sizeof(jsonString) + "\r\n\r\n" +
    Serial.println(jsonString);
    //Serial.println(fullRequest);
    //client.print(fullRequest);

    char status[60] = {0};
    client.readBytesUntil('\r', status, sizeof(status));
    if (strcmp(status, "HTTP/1.0 200 OK") != 0) {
        Serial.print(F("[ ERROR ]\tUnexpected Response: "));
        Serial.println(status);
        return;
    }
    else
    {
        Serial.println(F("[ INFO ]\tGot a 200 OK."));
    }
    /**
    client.setServer(host, port);

    while (!client.connected()) {
        Serial.println("Connecting to server...");

        if (client.connect("ESP32Client", "admin", "admin" )) {
            Serial.println("connected");
        } else {
            Serial.print("failed with state ");
            Serial.println(client.state());
        }
        yield();
    }

    
  // Purge json string
  jsonBuffer.clear();
  JsonObject& root = jsonBuffer.createObject();
  JsonArray& mac = root.createNestedArray("MAC");
  // JsonArray& rssi = root.createNestedArray("RSSI");

  // add Beacons
  for (int u = 0; u < aps_known_count; u++) {
    deviceMac = formatMac1(aps_known[u].bssid);
    if (aps_known[u].rssi > MINRSSI) {
      mac.add(deviceMac);
      //    rssi.add(aps_known[u].rssi);
    }
  }

  // Add Clients
  for (int u = 0; u < clients_known_count; u++) {
    deviceMac = formatMac1(clients_known[u].station);
    if (clients_known[u].rssi > MINRSSI) {
      mac.add(deviceMac);
      //    rssi.add(clients_known[u].rssi);
    }
  }

  Serial.println();
  Serial.printf("number of devices: %02d\n", mac.size());
  root.prettyPrintTo(Serial);
  root.printTo(jsonString);
  //  Serial.println((jsonString));
  //  Serial.println(root.measureLength());
  if (client.publish("Sniffer", jsonString) == 1) Serial.println("Successfully published");
  else {
    Serial.println();
    Serial.println("!!!!! Not published. Please add #define MQTT_MAX_PACKET_SIZE 2048 at the beginning of PubSubClient.h file");
    Serial.println();
  }
  client.loop();
  client.disconnect ();**/

  delay(100);
  wifi_promiscuous_enable(enable);
  sendEntry = millis();
}

