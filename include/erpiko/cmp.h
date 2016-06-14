#ifndef _CMP_H_
#define _CMP_H_

#include "erpiko/certificate.h"
#include "erpiko/rsakey.h"
#include "erpiko/sim.h"
#include <string>
#include <memory>

namespace Erpiko {

  /**
   * CMP request status. See RFC4210 section 5.2.3
   */
  enum class CmpPKIStatus {
    // you got exactly what you asked for
    ACCEPTED = 0,
    // you got something like what you asked for; the
    // requester is responsible for ascertaining the differences
    GRANTED_WITH_MODS,
    // you don't get it, more information elsewhere in the message
    REJECTION,
    // the request body part has not yet been processed; expect to
    // hear more later (note: proper handling of this status
    // response MAY use the polling req/rep PKIMessages specified
    // in Section 5.3.22; alternatively, polling in the underlying
    // transport layer MAY have some utility in this regard)
    WAITING,
    // this message contains a warning that a revocation is imminent
    REVOCATION_WARNING,
    // notification that a revocation has occurred
    REVOCATION_NOTIFICATION,
    //  update already done for the oldCertId specified in
    //  CertReqMsg
    KEY_UPDATE_WARNING
  };

/**
 * Handles CMP request
 */
class Cmp {
  public:
    Cmp();
    virtual ~Cmp();

    /**
     * Sets server path
     * @param serverPath path of the CMP service
     */
    void serverPath(const std::string serverPath);

    /**
     * Sets server name
     * @param serverName FQDN of the server
     */
    void serverName(const std::string serverName);

    /**
     * Sets server port
     * @param serverPort port of the server
     */
    void serverPort(const int serverPort);



    /**
     * Sets reference
     * @param referenceName
     */
    void referenceName(const std::string referenceName);

    /**
     * Sets secret
     * @param secretValue the secret we set for the request
     */
    void secret(const std::string secretValue);

    /**
     * Set private key
     * @param privateKey the private key we use for the request
     */
    void privateKey(const RsaKey& privateKey);

    /**
     * Set CA cert
     * @param cert the CA certificate we use for the request
     */
    void caCertificate(const Certificate& cert);

    /**
     * Set subject
     * @param subject the identity assigned to this request
     */
    void subject(const Identity& identity);

    /**
     * Starts initialization request
     */
    const Certificate* startInitRequest();

    /**
     * Inserts SIM into CMP request
     * @param sim The SIM to be inserted
     */
    void insertSim(const Sim& sim);

    /**
     * Set option whether to use TLS
     * @param enabled True if TLS is used
     */
    void useTls(bool enabled);

  private:
    class Impl;
    std::unique_ptr<Impl> impl;
};

} // namespace Erpiko
#endif // _CMP_H_
