from mininet.topo import Topo

class MyTopo( Topo ):
    "Simple topology example."

    def build( self ):
        "Create custom topo."

        # Add hosts and switches
        leftHost = self.addHost( 'h1' )
        rightHost = self.addHost( 'h2' )
        Switch = self.addSwitch( 's1' )
        Switch2 = self.addSwitch( 's2' )
        Switch3 = self.addSwitch( 's3' )
        Switch4 = self.addSwitch( 's4' )
        Switch5 = self.addSwitch( 's5' )

        # Add links
        self.addLink( leftHost, Switch )
        self.addLink(Switch, Switch2)
        self.addLink(Switch2, Switch3)
        self.addLink(Switch3, Switch4)
        self.addLink(Switch4, Switch5)
        self.addLink( Switch5, rightHost )


topos = { 'mytopo': ( lambda: MyTopo() ) }
