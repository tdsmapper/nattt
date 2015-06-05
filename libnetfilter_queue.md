From:
http://lists.netfilter.org/pipermail/netfilter-devel/2006-February/023286.html



---

nfq\_open()

---


Prototype:
> struct nfq\_handle **nfq\_open(void)**

Parameters:
> None.

Returns:
> Pointer to a new queue handle or NULL on failure.

Description:
> Obtains a netfilter queue connection handle.  When you are
> finished with the handle returned by this function, you should
> destroy it by calling nfq\_close().  A new netlink connection
> is obtained internally and associated with the queue
> connection handle returned.


---

nfq\_open\_nfnl()

---


Prototype:
> struct nfq\_handle **nfq\_open\_nfnl(struct nfnl\_handle**nfnlh)

Parameters:

> nfnlh	Netfilter netlink connection handle obtained by
> > calling nfnl\_open()

Returns:

> Pointer to a new queue handle or NULL on failure.

Description:
> Obtains a netfilter queue connection handle using an existing
> netlink connection.  This function is used internally to
> implement nfq\_open(), and should typically not be called
> directly.


---

nfq\_close()

---


Prototype:
> int nfq\_close(struct nfq\_handle **h)**

Parameters:
> h	Netfilter queue connection handle obtained via
> > call to nfq\_open()

Returns:

> 0 on success, non-zero on failure (see nfnl\_close() return
> > value)

Description:

> Close connection associated with the queue connection handle
> and free associated resources.


---

nfq\_nfnlh()

---


Prototype:
> struct nfnl\_handle **nfq\_nfnlh(struct nfq\_handle**h)

Parameters:
> h	Netfilter queue connection handle obtained via call to
> > nfq\_open()

Returns:

> The netlink handle assocated with the given queue connection
> handle.  If passed an invalid handle, this function will more
> than likely cause a segfault as it performs no checks on the
> provided handle.

Description:
> Returns the netlink handle associated with the given queue
> connection handle.  Possibly useful if you wish to perform
> other netlink communication directly after opening a queue
> without opening a new netlink connection to do so.


---

nfq\_fd()

---


Prototype:
> int nfq\_fd(struct nfq\_handle **h)**

Parameters:
> h	Netfilter queue connection handle obtained via call to
> > nfq\_open()

Returns:

> A file descriptor that can be used for communication over the
> netlink connection associated with the given queue connection
> handle.  On failure, returns ??? -1 ???. (See nfnl\_fd() return
> value)

Description:
> Returns a file descriptor for the netlink connection
> associated with the given queue connection handle.  The file
> descriptor can then be used for receiving the queued packets
> for processing.

> Example:

> fd = nfq\_fd(h);

> while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
> printf("pkt received\n");
> nfq\_handle\_packet(h, buf, rv);
> > }


---

nfq\_bind\_pf()

---


Prototype:

> int nfq\_bind\_pf(struct nfq\_handle **h, u\_int16\_t pf)**

Parameters:

> h	Netfilter queue connection handle obtained via call to
> > nfq\_open()

> pf	Protocol family to bind handle to

Returns:
> ??? (See nfnl\_talk() return value)

Description:
> Binds the given queue connection handle to process packets
> belonging to the given protocol family (ie. PF\_INET, PF\_INET6,
> etc).

How many applications can bind to a given PF?
Is it per-queue, or per PF only?

??? Investigate kernel code to verify NFQNL\_CFG\_CMD\_PF\_BIND ???


---

nfq\_unbind\_pf()

---


Prototype:
> int nfq\_unbind\_pf(struct nfq\_handle **h, u\_int16\_t pf)**

Parameters:
> h	Netfilter queue connection handle obtained via call to
> > nfq\_open()

> pf	Protocol family to unbind family from

Returns:
> ??? (See nfnl\_talk() return value)

Description:
> Unbinds the given queue connection handle from processing
> packets belonging to the given protocol family.

??? Investigate kernel code NFQNL\_CFG\_CMD\_PF\_UNBIND ???


---

nfq\_create\_queue()

---


Prototype:

> struct nfq\_q\_handle **nfq\_create\_queue(struct nfq\_handle**h,
> > u\_int16\_t num, nfq\_callback **cb, void**data)

Parameters:

> h	Netfilter queue connection handle obtained via call to
> > nfq\_open()

> num	The number of the queue to bind to
> cb	Callback function to call for each queued packet
> data	Custom data to pass to the callback function

Returns:
> A new queue handle. (Actually a pointer to a linked list entry
> maintained by the libnetfilter\_queue library) Returns NULL on
> failure.

Description:
> Creates a new queue handle, and returns it.  The new queue is
> identified by 

&lt;num&gt;

, and the callback specified by 

&lt;cb&gt;

 will
> be called for each enqueued packet.  The 

&lt;data&gt;

 argument will
> be passed unchanged to the callback.  If a queue entry with id
> 

&lt;num&gt;

 already exists, this function will return failure and
> the existing entry is unchanged.

The nfq\_callback type is defined in
"libnetfilter\_queue/libnetfilter\_queue.h" as:

> typedef int nfq\_callback(struct nfq\_q\_handle **qh,
> > struct nfgenmsg**nfmsg, struct nfq\_data **nfad, void**data);


> Parameters:

> qh	The queue handle returned by nfq\_create\_queue
> nfmsg	???
> nfq\_data Netlink packet data handle (required as parameter of
> > many of the informational functions)

> data	??? The value passed to the data parameter of
> > nfq\_create\_queue


> Returns:
> The callback should return ???

> /**General form of address family dependent message.
    * Defined in "libnfnetlink/linux\_libnfnetlink.h"
    * 
> struct nfgenmsg {
> > u\_int8\_t  nfgen\_family;		/** AF\_xxx **/
> > u\_int8\_t  version;		/** nfnetlink version **/
> > u\_int16\_t res\_id;		/** resource id **/

> } attribute ((packed));**


??? How many queues can exist?
> - Could be unlimited.  Library implements as linked list.

??? Can multiple apps bind to the same queue?
> - looks like it's per app on lib side
> - ...need to check out kernel side implementation...

??? Can separate queues be processed separately by separate apps?

??? Investigate kernel code NFQNL\_CFG\_CMD\_BIND ???


---

nfq\_destroy\_queue()

---


Prototype:
> int nfq\_destroy\_queue(struct nfq\_q\_handle **qh)**

Parameters:
> qh	Netfilter queue handle obtained by call to
> > nfq\_create\_queue().

Returns:

> 0 on success, non-zero on failure.  (See NFQNL\_CFG\_CMD\_UNBIND
> return value)

Description:
> Removes the binding for the specified queue handle.  (The
> queue handles are maintained in the libnetfilter\_queue library
> as a linked list.  The 

&lt;qh&gt;

 is actually just a pointer to an
> entry in that list.  When unbinding, a NFQNL\_CFG\_CMD\_UNBIND
> message is sent to netlink, and if successful, the handle
> entry is removed from the linked list)

??? Investigate kernel code NFQNL\_CFG\_CMD\_UNBIND ???


---

nfq\_handle\_packet()

---


Prototype:
> int nfq\_handle\_packet(struct nfq\_handle **h, char**buf, int len)

Parameters:
> h	Netfilter queue connection handle obtained via call to
> > nfq\_open()

> buf	Buffer containing packet data to process
> len	Length of packet data in buffer

Returns:
> Returns 0 on success, non-zero on failure. (See
> nfnl\_handle\_packet() return value)

Description:
> Triggers an associated callback for the given packet received
> from the queue.  Packets can be read from the queue using
> nfq\_fd() and recv().  See example code for nfq\_fd().


---

nfq\_set\_mode()

---


Prototype:
> int nfq\_set\_mode(struct nfq\_q\_handle **qh, u\_int8\_t mode,
> > u\_int32\_t range)**

Parameters:

> qh	Netfilter queue handle obtained by call to
> > nfq\_create\_queue().

> mode	NFQNL\_COPY\_NONE		??? Do not copy any data
> > NFQNL\_COPY\_META		??? Copy only packet metadata
> > NFQNL\_COPY\_PACKET	??? Copy entire packet

> range	??

Returns:
> 0 on success, non-zero on failure. (see nfnl\_talk() return
> value)

Description:
> Sets the amount of data to be copied to userspace for each
> packet queued to the given queue. ???


---

nfq\_set\_verdict()

---


Prototype:
> int nfq\_set\_verdict(struct nfq\_q\_handle **qh, u\_int32\_t id,
> > u\_int32\_t verdict, u\_int32\_t data\_len, unsigned char**buf)

Parameters:

> qh	Netfilter queue handle obtained by call to
> > nfq\_create\_queue().

> id	ID assigned to packet by netfilter.  Can be obtained
> > by:
> > int id;
> > struct nfqnl\_msg\_packet\_hdr **ph =
> > > nfq\_get\_msg\_packet\_hdr(tb);

> > if (ph) id = ntohl(ph->packet\_id);

> verdict	Verdict to return to netfilter
> > NF\_ACCEPT	- Accept the packet
> > NF\_DROP		- Drop the packet
> > ???		- anything else possible? (ie. continue?,
> > > jump? goto? log?)

> data\_len ??? Number of bytes of data pointed to by**

&lt;buf&gt;


> buf	??? Pointer to data buffer...

Returns:
> 0 on success, non-zero on failure.  (See nfnl\_sendiov() return
> value)

Description:
> Notifies netfilter of the userspace verdict for the given
> packet.  Every queued packet _must_ have a verdict specified
> by userspace, either by calling this function, or by calling
> the nfq\_set\_verdict\_mark() function.


---

nfq\_set\_verdict\_mark()

---


Prototype:
> int nfq\_set\_verdict\_mark(struct nfq\_q\_handle **qh, u\_int32\_t id,
> > u\_int32\_t verdict, u\_int32\_t mark, u\_int32\_t data\_len,
> > > unsigned char**buf)

Parameters:

> qh	Netfilter queue handle obtained by call to
> > nfq\_create\_queue().

> id	ID assigned to packet by netfilter.  Can be obtained by:
> > ph = nfq\_get\_msg\_packet\_hdr(tb);
> > if (ph) id = ntohl(ph->packet\_id);

> verdict	Verdict to return to netfilter
> > NF\_ACCEPT	- Accept the packet
> > NF\_DROP		- Drop the packet
> > ???		- anything else possible? (ie. continue?,
> > > jump? goto? log?)

> mark	Netfilter mark value to mark packet with
> data\_len ??? Number of bytes of data pointed to by 

&lt;buf&gt;


> buf	??? Pointer to data buffer...

Returns:
> 0 on success, non-zero on failure.  (See nfnl\_sendiov() return
> value)

Description:
> Notifies netfilter of the userspace verdict for the given
> packet, and also marks the packet with the given netfilter
> mark value.  Every queued packet _must_ have a verdict
> specified by userspace, either by calling this function, or by
> calling the nfq\_set\_verdict() function.


---

nfq\_get\_msg\_packet\_hdr()

---


Prototype:
> struct nfqnl\_msg\_packet\_hdr **nfq\_get\_msg\_packet\_hdr
> > (struct nfq\_data**nfad)

Parameters:

> nfad	Netlink packet data handle passed to callback function

Returns:
> Returns the netlink packet header for the given packet data.

Description:
> Returns the netfilter queue netlink packet header for the
> given nfq\_data argument.  Typically, the nfq\_data value is
> passed as the 3rd parameter to the callback function set by a
> call to nfq\_create\_queue().

> The nfqnl\_msg\_packet\_hdr structure is defined in
> "libnetfilter\_queue/libnetfilter\_queue.h" as:

> struct nfqnl\_msg\_packet\_hdr {
> > u\_int32\_t  packet\_id;/**unique ID of packet in queue**/
> > u\_int16\_t  hw\_protocol;/**hw protocol (network order)**/
> > u\_int8\_t   hook;/**netfilter hook**/

> } attribute ((packed));


---

nfq\_get\_nfmark()

---


Prototype:
> uint32\_t nfq\_get\_nfmark(struct nfq\_data **nfad)**

Parameters:
> nfad	Netlink packet data handle passed to callback function

Returns:
> The netfilter mark currently assigned to the packet.

Description:
> Returns the netfilter mark currently assigned to the given
> queued packet.


---

nfq\_get\_timestamp()

---


Prototype:
> int nfq\_get\_timestamp(struct nfq\_data **nfad, struct timeval**tv)

Parameters:
> nfad	Netlink packet data handle passed to callback function
> tv		Structure to fill with timestamp info

Returns:
> 0 on success, non-zero on failure.

Description:
> Retrieves the received timestamp when the given queued packet.


---

nfq\_get\_indev()

---


Prototype:
> u\_int32\_t nfq\_get\_indev(struct nfq\_data **nfad)**

Parameters:
> nfad	Netlink packet data handle passed to callback function

Returns:
> The index of the device the queued packet was received via.
> If the returned index is 0, the packet was locally generated
> or the input interface is no longer known (ie. POSTROUTING?).

Description:
> Retrieves the interface that the queued packet was received
> through.


---

nfq\_get\_physindev()

---


Prototype:
> u\_int32\_t nfq\_get\_physindev(struct nfq\_data **nfad)**

Parameters:
> nfad	Netlink packet data handle passed to callback function

Returns:
> The index of the physical device the queued packet was
> received via.  If the returned index is 0, the packet was
> locally generated or the physical input interface is no longer
> known (ie. POSTROUTING?).

Description:
> Retrieves the physical interface that the queued packet was
> received through.


---

nfq\_get\_outdev()

---


Prototype:
> u\_int32\_t nfq\_get\_outdev(struct nfq\_data **nfad)**

Parameters:
> nfad	Netlink packet data handle passed to callback function

Returns:
> The index of the device the queued packet will be sent out.
> If the returned index is 0, the packet is destined for
> localhost or the output interface is not yet known
> (ie. PREROUTING?).

Description:
> Retrieves the interface that the queued packet will be routed
> out.


---

nfq\_get\_physoutdev()

---


Prototype:
> u\_int32\_t nfq\_get\_physoutdev(struct nfq\_data **nfad)**

Parameters:
> nfad	Netlink packet data handle passed to callback function

Returns:
> The index of the physical device the queued packet will be
> sent out.  If the returned index is 0, the packet is destined
> for localhost or the physical output interface is not yet
> known (ie. PREROUTING?).

Description:
> Retrieves the physical interface that the queued packet will
> be routed out.


---

nfq\_get\_packet\_hw()

---


Prototype:
> struct nfqnl\_msg\_packet\_hw **nfq\_get\_packet\_hw
> > (struct nfq\_data**nfad)

Parameters:

> nfad	Netlink packet data handle passed to callback function

Returns:
> The source hardware address associated with the queued packet,
> or NULL if unknown.

Description:
> Retrieves the hardware address associated with the given
> queued packet.  For ethernet packets, the hardware address
> returned (if any) will be the MAC address of the packet source
> host.  The destination MAC address is not known until after
> POSTROUTING and a successful ARP request, so cannot currently
> be retrieved.

> The nfqnl\_msg\_packet\_hw structure is defined in
> "libnetfilter\_queue/libnetfilter\_queue.h" as:

> struct nfqnl\_msg\_packet\_hw {
> > u\_int16\_t	hw\_addrlen;
> > u\_int16\_t	_pad;
> > u\_int8\_t	hw\_addr[8](8.md);

> }__attribute__((packed));_


---

nfq\_get\_payload()

---


Prototype:
> int nfq\_get\_payload(struct nfq\_data **nfad, char****data)**

Parameters:
> nfad	Netlink packet data handle passed to callback function

Returns:
> The size of the data whose address is placed in 

&lt;data&gt;

 on
> success, -1 on failure.

Description:
> Retrieve the payload for a queued packet.  The actual amount
> and type of data retrieved by this function will depend on the
> mode set with the nfq\_set\_mode() function:
> > NFQNL\_COPY\_NONE		No data will be returned
> > NFQNL\_COPY\_META     Only packet headers will be returned
> > NFQNL\_COPY\_PACKET	Entire packet will be returned


---


---

From:
http://lists.netfilter.org/pipermail/netfilter-devel/2006-February/023286.html
