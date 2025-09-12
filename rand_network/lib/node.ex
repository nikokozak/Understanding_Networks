# A RAND network node, implemented as a GenServer.
# Each node maintains a table describing:
# - output/input links to other nodes
# - a directory of "known" nodes in the network (we're only connected to $NUM_NODE_CONNECTIONS)
# - the number of hops taken from said node to reach this node

# The state of this GenServer includes:
# - a list of hardware links to other nodes (implemented as Agents)
# - a stack of messages to process
# - a map of known nodes and their hop counts

# The state of this GenServer looks like:
# %{
#   node_map: %{{node_id, link_id} => hop_count, ...} # This functions as a 2-key map
# }

# Note that we **DO NOT** need to implement a stack, given that Erlang processes implement a message queue by default.
# As well, according to Elixir docs, we should not implement a receive loop for our GenServers.

defmodule Node do
  use GenServer

  # Client

  def start_link(default) when is_list(default) do
    GenServer.start_link(__MODULE__, default)
  end

  def push_packet(node_pid, packet) do
    GenServer.call(node_pid, {:incoming_packet, packet})
  end

  # Server (callbacks)

  @impl true
  def init(network_interface_pids) do
    state = %{
      name: self(),
      node_map: %{},
      # List of pids of HardwareLink processes
      interface_pids: network_interface_pids
    }

    {:ok, state}
  end

  @impl true
  def handle_call({:incoming_packet, packet}, from_local_interface_pid, state) do
    %{from_node: from_node_pid, to_node: to_node_pid, hops: hops, message: _message} =
      parsed_message = parse_packet(packet)

    state = update_node_map(state, from_node_pid, from_local_interface_pid, hops + 1)

    if is_this_node?(to_node_pid) do
      IO.puts("Message reached destination: #{inspect(parsed_message)}")
      # Mark as processed
      {:reply, :ok, :processed}
    else
      # Forward the packet to the fastest known route to the destination node
      # Otherwise send it out of a random link
      case fastest_route(state, to_node_pid) do
        {{_node, link_id}, _hops} ->
          if link_id != from_local_interface_pid do
            forward_packet(link_id, Packet.update_hops(packet))
          end

        nil ->
          # No known route to the destination node
          # Send it out of a random link
          Enum.random(
            state.interface_pids
            |> Enum.filter(fn ipid -> ipid != from_local_interface_pid end)
          )
          |> forward_packet(Packet.update_hops(packet))
      end

      {:reply, :ok, state}
    end
  end

  # Helper functions

  @spec forward_packet(pid(), any()) :: :ok
  def forward_packet(interface_pid, packet) do
    HardwareLink.transmit_packet(interface_pid, packet)
  end

  @spec parse_packet(Packet.t()) :: map()
  def parse_packet(packet) do
    Packet.parse_packet(packet)
  end

  @spec is_this_node?(pid()) :: boolean
  def is_this_node?(to_node) do
    to_node == self()
  end

  # Update the node map with the minimum hops to reach a given node via a given link
  @spec update_node_map(
          state :: map(),
          from_node :: pid(),
          link_id :: pid(),
          hops :: non_neg_integer()
        ) :: map()
  def update_node_map(state, from_node, link_id, hops) do
    Map.update(state, :node_map, state.node_map, fn node_map ->
      Map.update(node_map, {from_node, link_id}, hops, fn existing_hops ->
        min(existing_hops, hops)
      end)
    end)

    state
  end

  # Find the fastest route to a given node,
  # returning a tuple of {{node, link}, hops} or nil if no route exists
  @spec fastest_route(state :: map(), to_node :: pid()) ::
          {{pid(), pid()}, non_neg_integer()} | nil
  def fastest_route(state, to_node) do
    state.node_map
    |> Enum.filter(fn {{node, _link}, _hops} -> node == to_node end)
    |> Enum.min_by(fn {_key, hops} -> hops end, fn -> nil end)
  end
end
