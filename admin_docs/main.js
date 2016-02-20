var React = require('react');
var ReactDOM = require('react-dom');

var servers = [
    { name: "admin", href: "/servers/admin" },
    { name: "sysmon", href: "/servers/1" },
];

var ServerList = React.createClass({
    render: function () {
	var servers = this.props.servers.map(function (server) {
	    return (
		<Server href={server.href} name={server.name} />
		    );
	    });
	return (<div>{servers}</div>);
    }
});

var Server = React.createClass({
    render: function () {
	return (
	    <div className="server">
		name: <a href={this.props.href}>{this.props.name}</a>
	    </div>);
    }
});

ReactDOM.render(<ServerList servers={servers}/>,
		document.getElementById('servers'));
