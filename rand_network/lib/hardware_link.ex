# Hardware Link imitates a hardware interface, which should be owned by a Node GenServer

# The state of the HardwareLink should only be the pid of a paired HardwareLink, and the pid of its owner

defmodule HardwareLink do
  use Agent

  # The initial value should be a map with keys :owner and :paired_link
  # :owner is the pid of the Node that owns this HardwareLink
  # :paired_link is the pid of the HardwareLink that this HardwareLink is connected to
  def start_link(%{:owner => _owner, :peer_interface => _link} = state) do
    # Initial values are empty; they will be allocated in a round-robin and
    # then paired to a Node. Do NOT register a global name; we need many agents.
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
    peer_interface_pid = Agent.get(local_interface_pid, fn state ->
      Map.get(state, :peer_interface)
    end)

    case peer_interface_pid do
      nil -> :ok
      _ ->
        peer_owner = Agent.get(peer_interface_pid, fn peer_state ->
          Map.get(peer_state, :owner)
        end)

        case peer_owner do
          nil -> :ok
          peer -> RAND.Node.deliver_packet(peer, packet, peer_interface_pid)
        end
    end
  end
end
