/*****************************************************************************
 * | File         :   i2c.cpp
 * | Author       :   Waveshare team
 * | Function     :   Hardware underlying interface
 * | Info         :
 * |                 I2C driver code for I2C communication.
 * ----------------
 * | This version :   V1.1 (Defensive & Robust)
 * | Date         :   2024-11-26
 * | Info         :   Resilient error handling without fatal aborts
 *
 ******************************************************************************/

#include "i2c.h"  // Include I2C driver header for I2C functions
static const char *TAG = "i2c";  // Define a tag for logging

DEV_I2C_Port handle = { NULL, NULL };

DEV_I2C_Port DEV_I2C_Init()
{
    if (handle.bus != NULL) {
        return handle;  // Bus already initialized
    }

    // Define I2C bus configuration parameters
    i2c_master_bus_config_t i2c_bus_config = {
        .i2c_port = EXAMPLE_I2C_MASTER_NUM,     // I2C master port number
        .sda_io_num = EXAMPLE_I2C_MASTER_SDA,   // I2C SDA (data) pin
        .scl_io_num = EXAMPLE_I2C_MASTER_SCL,   // I2C SCL (clock) pin
        .clk_source = I2C_CLK_SRC_DEFAULT,       // Default clock source for I2C
        .glitch_ignore_cnt = 7,                  // Ignore glitches in the I2C signal
    };

    // Create a new I2C master bus with the above configuration
    esp_err_t err = i2c_new_master_bus(&i2c_bus_config, &handle.bus);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "i2c_new_master_bus failed: 0x%x", err);
        handle.bus = NULL;
    }

    return handle;
}

void DEV_I2C_Set_Slave_Addr(i2c_master_dev_handle_t *dev_handle, uint8_t Addr)
{
    if (!dev_handle) return;
    if (!handle.bus) {
        DEV_I2C_Init();
    }
    if (!handle.bus) return;

    // Avoid duplicate addition if handle already valid
    if (*dev_handle != NULL) return;

    // Configure the new device address
    i2c_device_config_t i2c_dev_conf = { 
        .device_address = Addr,                        // Set new device address
        .scl_speed_hz = EXAMPLE_I2C_MASTER_FREQUENCY,  // I2C frequency
    };
    
    // Add device to bus
    esp_err_t err = i2c_master_bus_add_device(handle.bus, &i2c_dev_conf, dev_handle);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "I2C add device (0x%02X) failed: 0x%x", Addr, err);
    }
}

void DEV_I2C_Write_Byte(i2c_master_dev_handle_t dev_handle, uint8_t Cmd, uint8_t value)
{
    if (!dev_handle) return;
    uint8_t data[2] = {Cmd, value};
    esp_err_t err = i2c_master_transmit(dev_handle, data, sizeof(data), 50);
    if (err != ESP_OK) {
        ESP_LOGD(TAG, "I2C Write_Byte failed: 0x%x", err);
    }
}

uint8_t DEV_I2C_Read_Byte(i2c_master_dev_handle_t dev_handle)
{
    if (!dev_handle) return 0;
    uint8_t data[1] = {0};
    esp_err_t err = i2c_master_receive(dev_handle, data, 1, 50);
    if (err != ESP_OK) {
        ESP_LOGD(TAG, "I2C Read_Byte failed: 0x%x", err);
    }
    return data[0];
}

uint16_t DEV_I2C_Read_Word(i2c_master_dev_handle_t dev_handle, uint8_t Cmd)
{
    if (!dev_handle) return 0;
    uint8_t data[2] = {Cmd, 0};
    esp_err_t err = i2c_master_transmit_receive(dev_handle, data, 1, data, 2, 50);
    if (err != ESP_OK) {
        ESP_LOGD(TAG, "I2C Read_Word failed: 0x%x", err);
        return 0;
    }
    return ((uint16_t)data[1] << 8) | data[0];
}

void DEV_I2C_Write_Nbyte(i2c_master_dev_handle_t dev_handle, uint8_t *pdata, uint8_t len)
{
    if (!dev_handle || !pdata || len == 0) return;
    esp_err_t err = i2c_master_transmit(dev_handle, pdata, len, 50);
    if (err != ESP_OK) {
        ESP_LOGD(TAG, "I2C Write_Nbyte failed: 0x%x", err);
    }
}

void DEV_I2C_Read_Nbyte(i2c_master_dev_handle_t dev_handle, uint8_t Cmd, uint8_t *pdata, uint8_t len)
{
    if (!dev_handle || !pdata || len == 0) return;
    esp_err_t err = i2c_master_transmit_receive(dev_handle, &Cmd, 1, pdata, len, 50);
    if (err != ESP_OK) {
        ESP_LOGD(TAG, "I2C Read_Nbyte failed: 0x%x", err);
    }
}
