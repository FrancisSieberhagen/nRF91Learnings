#include <zephyr.h>
#include <bsd.h>
#include <net/socket.h>
#include <modem/lte_lc.h>
#include <net/tls_credentials.h>
#include <modem/modem_key_mgmt.h>
#include <modem/at_cmd.h>
#include <modem/at_notif.h>
#include <drivers/gpio.h>
#include <stdio.h>
#include "cJSON.h"

#define LED_PORT        DT_GPIO_LABEL(DT_ALIAS(led0), gpios)
#define LED1	 DT_GPIO_PIN(DT_ALIAS(led0), gpios)
#define LED2	 DT_GPIO_PIN(DT_ALIAS(led1), gpios)
#define LED3	 DT_GPIO_PIN(DT_ALIAS(led2), gpios)
#define LED4	 DT_GPIO_PIN(DT_ALIAS(led3), gpios)


static int server_socket;
static struct sockaddr_storage server;
static const char cert[] = {
    #include "../cert/NRFTestServerRootCA"
};
#define TLS_SEC_TAG 42

static const char at_CGPADDR[] = "AT+CGPADDR=0";
static const char at_CGCONTRDP[] = "AT+CGCONTRDP=0";
static const char at_CGDCONT[] = "AT+CGDCONT?";

#define IMEI_LEN 1024


LOG_MODULE_REGISTER(app, CONFIG_TEST1_LOG_LEVEL);

#if defined(CONFIG_BSD_LIBRARY)

/**@brief Recoverable BSD library error. */
void bsd_recoverable_error_handler(uint32_t err)
{
  printk("bsdlib recoverable error: %u\n", err);
}

/**@brief Irrecoverable BSD library error. */
void bsd_irrecoverable_error_handler(uint32_t err)
{
  printk("bsdlib irrecoverable error: %u\n", err);

  __ASSERT_NO_MSG(false);
}

#endif /* defined(CONFIG_BSD_LIBRARY) */

void main(void)
{
    int err;

    init_led();

    err = at_comms_init();
    __ASSERT(err == 0, "ERROR: at_comms_init error %s", err);

    err = cert_provision();
    __ASSERT(err == 0, "ERROR: cert_provision error %s", err);

    err = connect_lte();
    __ASSERT(err == 0, "ERROR: conntect_lte error %s", err);

    err = tcp_ip_resolve();
    __ASSERT(err == 0, "ERROR: tcp_ip_resolve error %s", err);

    for (;;) {
        led_off(LED2);

        LOG_INF("Connect to %s:%d", log_strdup(CONFIG_SERVER_HOST), CONFIG_SERVER_PORT);
        if (connect_to_server() == 0) {
            led_on(LED2);

            initiate_http_request();

            close(server_socket);
        } else {
            close(server_socket);
        }
        k_sleep(K_MSEC(1000));
    }
}

struct device *led_device;

void init_led()
{

    led_device = device_get_binding(LED_PORT);

    /* Set LED pin as output */
    gpio_pin_configure(led_device, DT_GPIO_PIN(DT_ALIAS(led0), gpios),
                       GPIO_OUTPUT_ACTIVE |
                       DT_GPIO_FLAGS(DT_ALIAS(led0), gpios));
    gpio_pin_configure(led_device, DT_GPIO_PIN(DT_ALIAS(led1), gpios),
                       GPIO_OUTPUT_ACTIVE |
                       DT_GPIO_FLAGS(DT_ALIAS(led1), gpios));
    gpio_pin_configure(led_device, DT_GPIO_PIN(DT_ALIAS(led2), gpios),
                       GPIO_OUTPUT_ACTIVE |
                       DT_GPIO_FLAGS(DT_ALIAS(led2), gpios));
    gpio_pin_configure(led_device, DT_GPIO_PIN(DT_ALIAS(led3), gpios),
                       GPIO_OUTPUT_ACTIVE |
                       DT_GPIO_FLAGS(DT_ALIAS(led3), gpios));

    led_off(LED1);
    led_off(LED2);
    led_off(LED3);
    led_off(LED4);
    led_on(LED1);
}


void led_on(char led)
{
    gpio_pin_set(led_device, led, 1);
}
void led_off(char led)
{
    gpio_pin_set(led_device, led, 0);

}

void led_on_off(char led, bool on_off)
{
    if (on_off)
    {
        led_on(led);
    } else {
        led_off(led);
    }
}

int at_comms_init(void)
{
	int err;

	err = at_cmd_init();
	if (err) {
		LOG_ERR("Failed to initialize AT commands, err %d\n", err);
		return err;
	}

	err = at_notif_init();
	if (err) {
		LOG_ERR("Failed to initialize AT notifications, err %d\n", err);
		return err;
	}

	return 0;
}

void connect_lte(void)
{
    int err;

    err = lte_lc_init_and_connect();
    __ASSERT(err == 0, "ERROR: LTE link init and connect %d\n", err);

    err = lte_lc_psm_req(false);
    __ASSERT(err == 0, "ERROR: psm %d\n", err);

    err = lte_lc_edrx_req(false);
    __ASSERT(err == 0, "ERROR: edrx %d\n", err);

    LOG_INF("Connected to LTE network");
}

/* Provision certificate to modem */
int cert_provision(void)
{
	int err;
	bool exists;
	u8_t unused;

	LOG_INF("Check if there is existing certs on modem");

	err = modem_key_mgmt_exists(TLS_SEC_TAG,
				    MODEM_KEY_MGMT_CRED_TYPE_CA_CHAIN,
				    &exists, &unused);
	if (err) {
		LOG_ERR("Failed to check for certificates err %d\n", err);
		return err;
	}

	if (exists) {
		LOG_INF("Delete existing certs from modem");

		/* For the sake of simplicity we delete what is provisioned
		 * with our security tag and re provision our certificate.
		 */
		err = modem_key_mgmt_delete(TLS_SEC_TAG, MODEM_KEY_MGMT_CRED_TYPE_CA_CHAIN);
		if (err) {
			LOG_ERR("Failed to delete existing certificate, err %d\n", err);
            return err;
		}
	}

	LOG_INF("Provisioning certificate\n");

	/*  Provision certificate to the modem */
	err = modem_key_mgmt_write(TLS_SEC_TAG,
				   MODEM_KEY_MGMT_CRED_TYPE_CA_CHAIN,
				   cert, sizeof(cert) - 1);
	if (err) {
		LOG_ERR("Failed to provision certificate, err %d\n", err);
		return err;
	}

	LOG_INF("Certificate Provisioned\n");

	return 0;
}

/* Setup TLS options on a given socket */
int tls_setup(int fd)
{
	int err;
	int verify;

	/* Security tag that we have provisioned the certificate with */
	const sec_tag_t tls_sec_tag[] = {
		TLS_SEC_TAG,
	};

	/* Set up TLS peer verification */
	enum {
		NONE = 0,
		OPTIONAL = 1,
		REQUIRED = 2,
	};

	verify = REQUIRED;

	err = setsockopt(fd, SOL_TLS, TLS_PEER_VERIFY, &verify, sizeof(verify));
	if (err) {
		LOG_ERR("Failed to setup peer verification, err %d\n", errno);
		return err;
	}

	/* Associate the socket with the security tag
	 * we have provisioned the certificate with.
	 */
	err = setsockopt(fd, SOL_TLS, TLS_SEC_TAG_LIST, tls_sec_tag,
			 sizeof(tls_sec_tag));
	if (err) {
		LOG_ERR("Failed to setup TLS sec tag, err %d\n", errno);
		return err;
	}

	return 0;
}

int tcp_ip_resolve(void)
{
    struct addrinfo *addrinfo;

    struct addrinfo hints = {
      .ai_family = AF_INET,
      .ai_socktype = SOCK_STREAM
      };

    char ipv4_addr[NET_IPV4_ADDR_LEN];

    if (getaddrinfo(CONFIG_SERVER_HOST, NULL, &hints, &addrinfo) != 0)
    {
        LOG_ERR("ERROR: getaddrinfo failed\n");
        return -EIO;
    }

    if (addrinfo == NULL)
    {
        LOG_ERR("ERROR: Address not found\n");
        return -ENOENT;
    }

    struct sockaddr_in *server_ipv4 = ((struct sockaddr_in *)&server);

    server_ipv4->sin_addr.s_addr = ((struct sockaddr_in *)addrinfo->ai_addr)->sin_addr.s_addr;
    server_ipv4->sin_family = AF_INET;
    server_ipv4->sin_port = htons(CONFIG_SERVER_PORT);

    inet_ntop(AF_INET, &server_ipv4->sin_addr.s_addr, ipv4_addr, sizeof(ipv4_addr));
    LOG_INF("Server IPv4 Address %s\n", log_strdup(ipv4_addr));

    freeaddrinfo(addrinfo);

    return 0;
}

int connect_to_server()
{
    int err;

    if (CONFIG_TLS_ENABLED)
    {
        server_socket = socket(PF_INET, SOCK_STREAM, IPPROTO_TLS_1_2);
        tls_setup(server_socket);
    } else {
        server_socket = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    }
    
    if (server_socket < 0)
    {
        LOG_ERR("Failed to create CoAP socket: %d.\n", errno);
        return -errno;
    }

    err = connect(server_socket, (struct sockaddr *)&server,
                  sizeof(struct sockaddr_in));
    if (err < 0)
    {
        LOG_ERR("Connect failed : %d\n", errno);
        return -errno;
    }

    return 0;
}

int initiate_http_request()
{
    int responseCode = send_tcp_request();

    if (responseCode != 0)
    {
        return responseCode;
    }
    

    responseCode =receive_tcp_request();

    if (responseCode != 0)
    {
        return responseCode;
    }

    // TODO extract json from http packet and apply action
    // action_json_msg(msgbuf);

    return 0;
}

int send_tcp_request(){
    int bytes;
    size_t off = 0;
    char httpSendBuffer[] = "GET / HTTP/1.1\r\n"\
                            "Connection: keep-alive\r\n"\
                            "Accept: application/json\r\n"\
                            "Host: 139.162.251.115:42512\r\n\r\n";
    char httpBufferLength = strlen(httpSendBuffer);

    LOG_INF("Send packet data To %s:%d.", log_strdup(CONFIG_SERVER_HOST), CONFIG_SERVER_PORT);
	do {
		bytes = send(server_socket, &httpSendBuffer[off], httpBufferLength - off, 0);
		if (bytes < 0) {
            LOG_ERR("send() failed, err %d\n", errno);
            return errno;
		}
		off += bytes;
	} while (off < httpBufferLength);

    LOG_INF("Sent %d bytes\n", off);

    return 0;
}

int receive_tcp_request(){
    int  receiveBufferSize = 8192;

    char httpReceiveBuffer[receiveBufferSize];

	int bytes;
    
    size_t off = 0;
	do {
		bytes = recv(server_socket, &httpReceiveBuffer[off], receiveBufferSize - off, 0);
		if (bytes < 0) {
            LOG_ERR("recv() failed, err %d\n", errno);
            return errno;
		}
		off += bytes;
	} while (bytes != 0 /* peer closed connection */);

    LOG_INF("Received %d bytes\n", off);

	LOG_INF("%s", httpReceiveBuffer);

    return 0;
}

void action_json_msg(char *msgbuf) {

    cJSON *monitor_json = cJSON_Parse(msgbuf);

    if (monitor_json == NULL)
    {
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL)
        {
            LOG_ERR("ERROR: cJSON Parse : %s\n", error_ptr);
            return;
        }
    }

    cJSON *value_name = cJSON_GetObjectItemCaseSensitive(monitor_json, "ActionName");
    if (cJSON_IsString(value_name) && (value_name->valuestring != NULL))
    {
        if (strcmp((value_name->valuestring),"BSD Test") == 0) {
            cJSON *value_led1 = cJSON_GetObjectItemCaseSensitive(monitor_json, "LED1");
            if (cJSON_IsString(value_name) && (value_name->valuestring != NULL)) {
                led_on_off(LED3, value_led1->valueint);
            }
            cJSON *value_led2 = cJSON_GetObjectItemCaseSensitive(monitor_json, "LED2");
            if (cJSON_IsString(value_name) && (value_name->valuestring != NULL)) {
                led_on_off(LED4, value_led2->valueint);
            }
        }
    }

    cJSON_Delete(monitor_json);
}