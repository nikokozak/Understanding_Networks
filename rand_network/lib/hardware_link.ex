# Hardware Link imitates a hardware interface, which should be owned by a Node GenServer

# The state of the HardwareLink should only be the pid of a paired HardwareLink, and the pid of its owner

defmodule HardwareLink do
  use Agent

  # The initial value should be a map with keys :owner and :paired_link
  # :owner is the pid of the Node that owns this HardwareLink
  # :peer_interface is the pid of the HardwareLink that this HardwareLink is connected to
  def start_link(%{:owner => _owner, :peer_interface => _link} = state) do
    # Initial values are empty; they will be allocated in a round-robin and
    # then paired to a Node.
    Agent.start_link(fn -> state end)
  end

  # Register a link, or hardware link, to another HardwareLink process
  def register_link(local_interface_pid, peer_interface_pid) do
    Agent.update(local_interface_pid, fn state ->
      Map.put(state, :peer_interface, peer_interface_pid)
    end)
  end

  def get_peer_interface(local_interface_pid) do
    Agent.get(local_interface_pid, fn state ->
      Map.get(state, :peer_interface)
    end)
  end

  # Register the owner of this HardwareLink, which should be a Node process
  def register_owner(local_interface_pid, owner_pid) do
    Agent.update(local_interface_pid, fn state ->
      Map.put(state, :owner, owner_pid)
    end)
  end

  def get_owner(local_interface_pid) do
    Agent.get(local_interface_pid, fn state ->
      Map.get(state, :owner)
    end)
  end

  def get_peer(local_interface_pid) do
    peer_interface_id = get_peer_interface(local_interface_pid)
    get_owner(peer_interface_id)
  end

  @spec transmit_packet(pid(), Packet.t()) :: :ok
  def transmit_packet(local_interface_pid, packet) do
    peer_interface_pid =
      Agent.get(local_interface_pid, fn state ->
        Map.get(state, :peer_interface)
      end)

    case peer_interface_pid do
      nil ->
        :ok

      _ ->
        Agent.get(peer_interface_pid, fn peer_state ->
          case Map.get(peer_state, :owner) do
            nil -> :ok
            peer -> RAND.Node.deliver_packet(peer, packet, peer_interface_pid)
          end
        end)

        :ok
    end
  end

  @doc """
  Attempt to transmit; returns :ok | :busy | :no_peer.
  Busy is simulated via a per-interface random probability.
  """
  @spec try_transmit(pid(), Packet.t()) :: :ok | :busy | :no_peer
  def try_transmit(local_interface_pid, packet) do
    # Check if there is a peer interface (get its pid)
    peer_interface_pid =
      Agent.get(local_interface_pid, fn state ->
        Map.get(state, :peer_interface)
      end)

    if is_nil(peer_interface_pid) do
      # No peer interface registered, bad luck
      :no_peer
    else
      # Check if we are busy by simulating a random probability
      busy_prob = Agent.get(local_interface_pid, fn state -> Map.get(state, :busy_prob, 0.0) end)

      if :rand.uniform() < busy_prob do
        # Oops, we are busy
        :busy
      else
        # Not busy, try to send the packet to the peer's owner
        # Importantly, this call is synchronous, so if the peer's owner is busy,
        # this will block until it can be processed. TODO: figure out if async is possible by implementing a GenServer
        # That said, it is OK with our model, in that the peer interface handles the actual passing and remote call.
        Agent.get(peer_interface_pid, fn peer_state ->
          case Map.get(peer_state, :owner) do
            nil ->
              :no_peer

            peer ->
              RAND.Node.deliver_packet(peer, packet, peer_interface_pid)
              :ok
          end
        end)
      end
    end
  end

  def set_busy_prob(local_interface_pid, prob) when is_number(prob) do
    p =
      prob
      |> max(0.0)
      |> min(1.0)

    Agent.update(local_interface_pid, fn state -> Map.put(state, :busy_prob, p) end)
  end
end
