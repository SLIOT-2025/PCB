#include <WiFi.h>
#include <Firebase_ESP_Client.h>
#include <SPI.h>
#include <MFRC522.h>
#include <ESP32Servo.h>


const char* ssid     = "Ravindu's Galaxy A12 ";     // Enter SSID name of your wifi router
const char* password = "smwd3183";    // Enter password of your wifi router

#define API_KEY "AIzaSyCzQYyV3DEf-CTT4064p0vWrz2zV0xqCbE"
#define DATABASE_URL "https://velocity-68b51-default-rtdb.asia-southeast1.firebasedatabase.app/"

#define USER_EMAIL "codecraftuom@gmail.com"
#define USER_PASSWORD "12345678"

#define ledpin1 25
#define ledpin2 26

FirebaseData fbdo;
FirebaseAuth auth;
FirebaseConfig config;

#define RST_PIN         5           // Configurable, see typical pin layout above
#define SS_PIN          21          // Configurable, see typical pin layout above

MFRC522 mfrc522(SS_PIN, RST_PIN);   // Create MFRC522 instance.

MFRC522::MIFARE_Key key;

int prelockState = 0;
unsigned long sendDataPrevMillis = 0;

Servo myservo;  // create servo object to control a servo
int pos = 0;    // variable to store the servo position
int servoPin = 32;

void setup()
{
    Serial.begin(115200);
    pinMode(ledpin1, OUTPUT);      // set the LED pin mode
    pinMode(ledpin2, OUTPUT);      // set the LED pin mode
    digitalWrite(ledpin1, LOW);
    digitalWrite(ledpin2, LOW);
    delay(10);

    // We start by connecting to a WiFi network

    Serial.print("Connecting to ");
    Serial.println(ssid);

    WiFi.begin(ssid, password);

    while (WiFi.status() != WL_CONNECTED) {
        delay(300);
        Serial.print(".");
    }

    Serial.println("");
    Serial.println("WiFi connected.");
    Serial.println("IP address: ");
    Serial.println(WiFi.localIP());

    ESP32PWM::allocateTimer(0);
    myservo.setPeriodHertz(50);    // standard 50 hz servo
    myservo.attach(servoPin, 1000, 2000);

    config.api_key = API_KEY;

    auth.user.email = USER_EMAIL;
    auth.user.password = USER_PASSWORD;

    /* Assign the RTDB URL (required) */
    config.database_url = DATABASE_URL;

    // Comment or pass false value when WiFi reconnection will control by your code or third party library e.g. WiFiManager
    Firebase.reconnectNetwork(true);

    // Since v4.4.x, BearSSL engine was used, the SSL buffer need to be set.
    // Large data transmission may require larger RX buffer, otherwise connection issue or data read time out can be occurred.
    fbdo.setBSSLBufferSize(4096 /* Rx buffer size in bytes from 512 - 16384 */, 1024 /* Tx buffer size in bytes from 512 - 16384 */);

    // Limit the size of response payload to be collected in FirebaseData
    fbdo.setResponseSize(2048);

    Firebase.begin(&config, &auth);

    Firebase.setDoubleDigits(5);

    config.timeout.serverResponse = 10 * 1000;

    SPI.begin();        // Init SPI bus
    mfrc522.PCD_Init(); // Init MFRC522 card

    for (byte i = 0; i < 6; i++) {
        key.keyByte[i] = 0xFF;
    }
    
    Serial.println(F("Scan a MIFARE Classic PICC to read."));
    dump_byte_array(key.keyByte, MFRC522::MF_KEY_SIZE);
    Serial.println();

}



void loop(){
  // Firebase.ready() should be called repeatedly to handle authentication tasks.
  if (Firebase.ready() && (millis() - sendDataPrevMillis > 1000 || sendDataPrevMillis == 0))
  {
    sendDataPrevMillis = millis();
    int lockState;
    if(Firebase.RTDB.getInt(&fbdo, "stations/-OLyKSYr0GRd40bCjsBc/locks/102/state", &lockState)){
    //lockState = 0 means open lock
      if(lockState == 0){
        digitalWrite(ledpin1, HIGH);
        digitalWrite(ledpin2, LOW);
        if (prelockState != lockState){
          openlock();
        }
        else if (prelockState == lockState){
          String BikeID = CheckRFID();
          String firstFour = BikeID.substring(0, 4);
          String Bikeaddr = "bicycles/" + firstFour + "/state";
          Serial.println(Bikeaddr);
          if (BikeID != "0"){
            while(!(Firebase.RTDB.setString(&fbdo, "stations/-OLyKSYr0GRd40bCjsBc/locks/102/bicycleId", firstFour)));
            while(!(Firebase.RTDB.setString(&fbdo, Bikeaddr, "locked")));
            //update Database
            while(!(Firebase.RTDB.setInt(&fbdo, "stations/-OLyKSYr0GRd40bCjsBc/locks/102/state", 1)));
            closelock();
            //closelock
          }
        } 
      }
      else{
        digitalWrite(ledpin1, LOW);
        digitalWrite(ledpin2, HIGH);
        // Do nothing
      }

    }
    else{
    Serial.println(fbdo.errorReason().c_str());
    digitalWrite(ledpin1, LOW);
    digitalWrite(ledpin2, LOW);
    }
  prelockState = lockState;
  }
}
void openlock(){
  myservo.write(130);              // tell servo to go to position in variable 'pos'
  delay(1660);   
  myservo.write(90); 
  delay(30000);
}

void closelock(){
  myservo.write(45);              // tell servo to go to position in variable 'pos'
  delay(1700); 
  myservo.write(90); 
}

String CheckRFID(){
  // Reset the loop if no new card present on the sensor/reader. This saves the entire process when idle.
    // Reset the loop if no new card present on the sensor/reader. This saves the entire process when idle.
    if ( ! mfrc522.PICC_IsNewCardPresent())
        return "0";

    // Select one of the cards
    if ( ! mfrc522.PICC_ReadCardSerial())
        return "0";

    // Show some details of the PICC (that is: the tag/card)
    Serial.print(F("Card UID:"));
    dump_byte_array(mfrc522.uid.uidByte, mfrc522.uid.size);
    Serial.println();
    Serial.print(F("PICC type: "));
    MFRC522::PICC_Type piccType = mfrc522.PICC_GetType(mfrc522.uid.sak);
    Serial.println(mfrc522.PICC_GetTypeName(piccType));

    // Check for compatibility
    if (    piccType != MFRC522::PICC_TYPE_MIFARE_MINI
        &&  piccType != MFRC522::PICC_TYPE_MIFARE_1K
        &&  piccType != MFRC522::PICC_TYPE_MIFARE_4K) {
        Serial.println(F("This sample only works with MIFARE Classic cards."));
        return "0";
    }

    // In this sample we use the second sector,
    // that is: sector #1, covering block #4 up to and including block #7
    byte sector         = 1;
    byte blockAddr      = 4;
    byte trailerBlock   = 7;
    MFRC522::StatusCode status;
    byte buffer[18];
    byte size = sizeof(buffer);

    // Authenticate using key A
    Serial.println(F("Authenticating using key A..."));
    status = (MFRC522::StatusCode) mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, trailerBlock, &key, &(mfrc522.uid));
    if (status != MFRC522::STATUS_OK) {
        Serial.print(F("PCD_Authenticate() failed: "));
        Serial.println(mfrc522.GetStatusCodeName(status));
        return "0";
    }

    // Read data from the block
    Serial.print(F("Reading data from block ")); Serial.print(blockAddr);
    Serial.println(F(" ..."));
    status = (MFRC522::StatusCode) mfrc522.MIFARE_Read(blockAddr, buffer, &size);
    if (status != MFRC522::STATUS_OK) {
        Serial.print(F("MIFARE_Read() failed: "));
        Serial.println(mfrc522.GetStatusCodeName(status));
        return "0";
    }

    Serial.print(F("Data in block ")); Serial.print(blockAddr); Serial.println(F(":"));
    String RFID = (char*)buffer;
    Serial.println(RFID);
    Serial.println();

    // Halt PICC
    mfrc522.PICC_HaltA();
    // Stop encryption on PCD
    mfrc522.PCD_StopCrypto1();

    return RFID;
}

void dump_byte_array(byte *buffer, byte bufferSize) {
    for (byte i = 0; i < bufferSize; i++) {
        Serial.print(buffer[i] < 0x10 ? " 0" : " ");
        Serial.print(buffer[i], HEX);
    }
}
